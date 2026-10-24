/*
  Sentinel başlangıç kuralları.
  Kendi kurallarını bu klasöre ekle; imza sürümü otomatik yenilenir.
  Not: `sentinel init` bu dosyayı %ProgramData%\Sentinel\rules\yara altına da yazar.
*/

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Encoded PowerShell command line in a script"
        severity = "high"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}

rule Suspicious_Download_And_Execute
{
    meta:
        description = "Script downloads and runs remote content"
        severity = "high"
    strings:
        $a = "DownloadString" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "WinHttp.WinHttpRequest" nocase
        $d = "Start-Process" nocase
    condition:
        any of ($a, $b, $c) and $d
}

rule Suspicious_Lnk_Shell_Command
{
    meta:
        description = "LNK shortcut spawning a shell"
        severity = "high"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $a = "powershell" nocase
        $b = "cmd.exe" nocase
        $c = "wscript" nocase
    condition:
        $lnk at 0 and any of ($a, $b, $c)
}
