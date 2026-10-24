#requires -Version 5.1
<#
.SYNOPSIS
  Sentinel'in AppLocker tabanli guven listesi araci.

.DESCRIPTION
  Smart App Control'un aksine AppLocker'da kural yazmak mumkun:
  yayinci (sertifika), hash veya klasor yolu bazinda izin verirsin.

  Bu betik kendi kural listesini tutar (%ProgramData%\Sentinel\applocker\rules.json),
  buradan bir AppLocker politikasi uretir ve uygular.

  Modlar:
    off     -> politika uygulanmaz (varsayilan; hicbir sey engellenmez)
    audit   -> kurallar calisir ama sadece loglar (kim engellenirdi gorursun)
    enforce -> kural disindaki exe/script'ler engellenir

  UYARI: enforce moduna gecmeden once audit modunda en az birkac gun calistir.
  Variable allowlist yanlissa uygulamalarin acilmaz.

.EXAMPLE
  .\applocker-trust.ps1 status
  .\applocker-trust.ps1 add -Path 'C:\WoM2' -Reason 'WoM2 istemcisi'
  .\applocker-trust.ps1 mode -Value audit
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('status', 'list', 'add', 'remove', 'mode', 'reset', 'apply', 'describe')]
    [string]$Command,

    [string]$Path,
    [ValidateSet('auto', 'publisher', 'hash', 'path')][string]$Kind = 'auto',
    [string]$Reason = '',
    [string]$Id = '',
    [ValidateSet('off', 'audit', 'enforce')][string]$Value = 'off',
    [string]$Root = '',
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

if (-not $Root) { $Root = Join-Path $env:ProgramData 'Sentinel' }
$stateDir = Join-Path $Root 'applocker'
$statePath = Join-Path $stateDir 'rules.json'
$policyPath = Join-Path $stateDir 'policy.xml'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-State {
    if (-not (Test-Path -LiteralPath $statePath)) {
        return [pscustomobject]@{ enforcement = 'off'; rules = @() }
    }
    $raw = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8
    if (-not $raw) { return [pscustomobject]@{ enforcement = 'off'; rules = @() } }
    $obj = $raw | ConvertFrom-Json
    $rules = @()
    if ($obj.rules) { $rules = @($obj.rules) }
    [pscustomobject]@{
        enforcement = $(if ($obj.enforcement) { $obj.enforcement } else { 'off' })
        rules       = $rules
    }
}

function Save-State($state) {
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Get-SacState {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    (Get-ItemProperty -Path $k -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
}

function Get-CollectionForExtension([string]$ext) {
    switch -Regex ($ext.ToLowerInvariant()) {
        '^\.(exe|com)$' { return 'Exe' }
        '^\.(ps1|bat|cmd|vbs|js|jse|wsf|wsh|psm1)$' { return 'Script' }
        '^\.(msi|msp|mst)$' { return 'Msi' }
        '^\.(dll|ocx)$' { return 'Dll' }
        default { return 'Exe' }
    }
}

# --- kural uretimi -------------------------------------------------------

function New-PathRule([string]$absPath) {
    $isDir = Test-Path -LiteralPath $absPath -PathType Container
    $pattern = if ($isDir) { "$absPath\*" } else { $absPath }
    $ruleId = [guid]::NewGuid().ToString()
    $name = "Sentinel: " + (Split-Path -Leaf $absPath)
    $xml = @"
    <FilePathRule Id="$ruleId" Name="$([Security.SecurityElement]::Escape($name))" Description="$([Security.SecurityElement]::Escape($Reason))" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="$([Security.SecurityElement]::Escape($pattern))" />
      </Conditions>
    </FilePathRule>
"@
    [pscustomobject]@{ id = $ruleId; kind = 'path'; target = $absPath; display = $pattern; xml = $xml; collection = (Get-CollectionForExtension ([IO.Path]::GetExtension($absPath))) }
}

function New-SignerRule([string]$absPath, [string]$ruleType) {
    $info = Get-AppLockerFileInformation -Path $absPath -ErrorAction Stop
    if (-not $info) { throw "Dosya bilgisi okunamadi: $absPath" }
    $pol = New-AppLockerPolicy -FileInformation $info -RuleType $ruleType -User 'S-1-1-0' -ErrorAction Stop
    [xml]$doc = $pol.ToXml()
    $rule = $null
    foreach ($rc in $doc.AppLockerPolicy.RuleCollection) {
        foreach ($node in $rc.ChildNodes) {
            if ($node.NodeType -eq 'Element' -and ($node.LocalName -eq 'FilePublisherRule' -or $node.LocalName -eq 'FileHashRule')) {
                $rule = $node
                break
            }
        }
        if ($rule) { break }
    }
    if (-not $rule) { throw "Kural uretilemedi ($ruleType): $absPath" }

    $ruleId = [guid]::NewGuid().ToString()
    $rule.SetAttribute('Id', $ruleId)
    $leaf = Split-Path -Leaf $absPath
    $rule.SetAttribute('Name', "Sentinel: $leaf")
    if ($rule.HasAttribute('Description')) { $rule.SetAttribute('Description', $Reason) } else {
        $attr = $doc.CreateAttribute('Description'); $attr.Value = $Reason; [void]$rule.Attributes.Append($attr)
    }
    [void]$rule.SetAttribute('UserOrGroupSid', 'S-1-1-0')
    [void]$rule.SetAttribute('Action', 'Allow')

    # Yayinci kurali surum sabitlemesin: guncellemelerden sonra da calissin.
    if ($rule.LocalName -eq 'FilePublisherRule') {
        $range = $rule.Conditions.FilePublisherCondition.BinaryVersionRange
        if ($range) {
            $range.SetAttribute('LowSection', '*')
            $range.SetAttribute('HighSection', '*')
        }
    }

    $display = $leaf
    $kindOut = $ruleType.ToLowerInvariant()
    if ($rule.LocalName -eq 'FilePublisherRule') {
        $pn = $rule.Conditions.FilePublisherCondition.PublisherName
        if ($pn) { $display = "$pn  ($leaf)" }
    }
    [pscustomobject]@{
        id         = $ruleId
        kind       = $kindOut
        target     = $absPath
        display    = $display
        xml        = $rule.OuterXml
        collection = (Get-CollectionForExtension ([IO.Path]::GetExtension($absPath)))
    }
}

function New-TrustRule([string]$target, [string]$kindWanted) {
    if (-not (Test-Path -LiteralPath $target)) { throw "Yol bulunamadi: $target" }
    $item = Get-Item -LiteralPath $target -Force
    $abs = $item.FullName

    if ($kindWanted -eq 'path') { return New-PathRule $abs }
    if ($item.PSIsContainer) { return New-PathRule $abs }
    if ($kindWanted -eq 'hash') { return New-SignerRule $abs 'Hash' }
    if ($kindWanted -eq 'publisher') { return New-SignerRule $abs 'Publisher' }

    # auto: imzali ise yayinci, degilse hash
    $sig = Get-AuthenticodeSignature -LiteralPath $abs
    if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
        try { return New-SignerRule $abs 'Publisher' } catch { }
    }
    return New-SignerRule $abs 'Hash'
}

# --- politika uretimi ----------------------------------------------------

function Build-PolicyXml($state) {
    $mode = switch ($state.enforcement) {
        'enforce' { 'Enabled' }
        'audit' { 'AuditOnly' }
        default { 'NotConfigured' }
    }

    # Politika sifirdan kurulur: AppLocker'in varsayilan Windows/Program Files
    # izinleri elle yazilir, aksi halde enforce modunda her sey kilitlenir.
    $doc = New-Object System.Xml.XmlDocument
    $decl = $doc.CreateXmlDeclaration('1.0', 'UTF-8', $null)
    [void]$doc.AppendChild($decl)
    $root = $doc.CreateElement('AppLockerPolicy')
    $root.SetAttribute('Version', '1')
    [void]$doc.AppendChild($root)

    function Add-DefaultRule($collectionNode, [string[]]$patterns, [string]$label) {
        foreach ($pattern in $patterns) {
            $r = $doc.CreateElement('FilePathRule')
            $r.SetAttribute('Id', [guid]::NewGuid().ToString())
            $r.SetAttribute('Name', "(Varsayilan) $label - $pattern")
            $r.SetAttribute('Description', 'AppLocker varsayilan izni')
            $r.SetAttribute('UserOrGroupSid', 'S-1-1-0')
            $r.SetAttribute('Action', 'Allow')
            $cond = $doc.CreateElement('Conditions')
            $fp = $doc.CreateElement('FilePathCondition')
            $fp.SetAttribute('Path', $pattern)
            [void]$cond.AppendChild($fp)
            [void]$r.AppendChild($cond)
            [void]$collectionNode.AppendChild($r)
        }
    }

    $collections = [ordered]@{
        'Exe'    = @('%PROGRAMFILES%\*', '%PROGRAMFILES(X86)%\*', '%WINDIR%\*')
        'Script' = @('%PROGRAMFILES%\*', '%PROGRAMFILES(X86)%\*', '%WINDIR%\*')
        'Msi'    = @('%WINDIR%\Installer\*')
    }

    foreach ($type in $collections.Keys) {
        $rc = $doc.CreateElement('RuleCollection')
        $rc.SetAttribute('Type', $type)
        $rc.SetAttribute('EnforcementMode', $mode)

        Add-DefaultRule $rc $collections[$type] $type
        [void]$root.AppendChild($rc)
    }

    foreach ($r in $state.rules) {
        $type = if ($r.collection) { $r.collection } else { 'Exe' }
        $rc = $null
        foreach ($c in $root.ChildNodes) { if ($c.LocalName -eq 'RuleCollection' -and $c.GetAttribute('Type') -eq $type) { $rc = $c } }
        if (-not $rc) { $rc = $root.FirstChild }
        $frag = $doc.CreateDocumentFragment()
        $frag.InnerXml = $r.xml
        [void]$rc.AppendChild($frag)
    }

    $doc.OuterXml
}

function Apply-Policy($state) {
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    # Mod kapaliyken koleksiyon birakmak AppLocker'i "varsayilan reddet" haline getirebilir
    # (sadece Program Files / Windows izinli kalir). Bu yuzden bos ilke yazilir.
    $xmlText = if ($state.enforcement -eq 'off') { '<AppLockerPolicy Version="1" />' } else { Build-PolicyXml $state }
    Set-Content -LiteralPath $policyPath -Value $xmlText -Encoding UTF8
    if (-not (Test-Admin)) {
        # Kapali modda yonetici yoksa yazacak bir sey de yok: politika zaten uygulanmamis olabilir.
        if ($state.enforcement -eq 'off') { return }
        throw 'Politikayi uygulamak icin yonetici PowerShell gerekli. Dosya yazildi: ' + $policyPath
    }
    Set-AppLockerPolicy -XmlPolicy $policyPath -ErrorAction Stop | Out-Null

    if ($state.enforcement -eq 'off') {
        # Kaldirma hemen etkili olmayabilir: yerel ilkeyi yenile ve AppID hizmetini yeniden baslat.
        try { & gpupdate.exe /force | Out-Null } catch { }
        try { & sc.exe stop AppIDSvc | Out-Null; Start-Sleep -Seconds 1; & sc.exe start AppIDSvc | Out-Null } catch { }
    }
}

# --- komutlar ------------------------------------------------------------

$state = Get-State

switch ($Command) {
    'status' {
        $svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
        $out = [pscustomobject]@{
            sac           = Get-SacState
            appIdService  = if ($svc) { "$($svc.Status)" } else { 'yok' }
            admin         = Test-Admin
            enforcement   = $state.enforcement
            ruleCount     = @($state.rules).Count
            statePath     = $statePath
            policyPath    = $policyPath
            appLockerCmdl = [bool](Get-Module -ListAvailable -Name AppLocker)
        }
    }
    'list' {
        $out = @($state.rules | ForEach-Object {
                [pscustomobject]@{
                    id       = $_.id
                    kind     = $_.kind
                    target   = $_.target
                    display  = $_.display
                    reason   = $_.reason
                    created  = $_.created
                    collection = $_.collection
                }
            })
    }
    'add' {
        if (-not $Path) { throw '-Path gerekli' }
        $rule = New-TrustRule $Path $Kind
        $entry = [pscustomobject]@{
            id         = $rule.id
            kind       = $rule.kind
            target     = $rule.target
            display    = $rule.display
            reason     = $Reason
            created    = (Get-Date).ToString('s')
            collection = $rule.collection
            xml        = $rule.xml
        }
        $state.rules = @($state.rules) + $entry
        Save-State $state
        if ($state.enforcement -ne 'off') { Apply-Policy $state }
        $out = [pscustomobject]@{ added = $true; rule = $entry; applied = ($state.enforcement -ne 'off') }
    }
    'describe' {
        if (-not $Path) { throw '-Path gerekli' }
        $rule = New-TrustRule $Path $Kind
        $out = [pscustomobject]@{ kind = $rule.kind; target = $rule.target; display = $rule.display; collection = $rule.collection }
    }
    'remove' {
        if (-not $Id) { throw '-Id gerekli' }
        $before = @($state.rules).Count
        $state.rules = @($state.rules | Where-Object { $_.id -ne $Id })
        if (@($state.rules).Count -eq $before) { throw "Kural bulunamadi: $Id" }
        Save-State $state
        if ($state.enforcement -ne 'off') { Apply-Policy $state }
        $out = [pscustomobject]@{ removed = $true; remaining = @($state.rules).Count }
    }
    'mode' {
        if (-not $PSBoundParameters.ContainsKey('Value')) { throw '-Value gerekli' }
        $state.enforcement = $Value
        Save-State $state
        Apply-Policy $state
        $out = [pscustomobject]@{ enforcement = $Value; applied = $true }
    }
    'apply' {
        Apply-Policy $state
        $out = [pscustomobject]@{ enforcement = $state.enforcement; applied = $true; rules = @($state.rules).Count }
    }
    'reset' {
        $state.rules = @()
        $state.enforcement = 'off'
        Save-State $state
        Apply-Policy $state
        $out = [pscustomobject]@{ reset = $true }
    }
}

if ($Json) {
    $out | ConvertTo-Json -Depth 8 -Compress
} else {
    $out | Format-List | Out-String -Width 300 | Write-Host
}
