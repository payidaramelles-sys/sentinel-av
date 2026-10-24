; Sentinel kurulum betiği (Inno Setup 6)
; Derlemek için: installer\build.ps1  ya da
;   ISCC.exe installer\Sentinel.iss

#define AppName "Sentinel"
#define AppVersion "1.0.0"
#define AppPublisher "Sentinel"
#define AppExe "Sentinel.exe"
#define ServiceName "Sentinel"

[Setup]
AppId={{8E4C1B36-7A2F-4E5B-9C1D-3F6A8D2E5B71}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppComments=Hafif Windows antivirus: Defender + YARA-X + ClamAV, sifreli karantina ve olay gunlugu
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=Sentinel-Setup-{#AppVersion}
SetupIconFile=sentinel.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
CloseApplications=no
AllowNoIcons=yes
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} kurulum
VersionInfoCompany={#AppPublisher}

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "desktopicon"; Description: "Masaüstü kısayolu oluştur"; GroupDescription: "Kısayollar:"
Name: "startup"; Description: "Windows açılışında tepsi simgesi olarak başlat"; GroupDescription: "Başlangıç:"
Name: "service"; Description: "Arka plan servisini kur (indirilenleri otomatik izler)"; GroupDescription: "Koruma:"

[Dirs]
; Servis LocalSystem, arayüz normal kullanıcı olarak çalışır: ikisi de aynı veriyi kullanabilsin.
Name: "{commonappdata}\{#AppName}"; Permissions: users-modify

[Files]
Source: "payload\app\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\cli\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "payload\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Olay raporu"; Filename: "{app}\cli\Sentinel.Cli.exe"; Parameters: "report"; WorkingDir: "{app}"
Name: "{group}\Kaldır"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
    ValueName: "Sentinel"; ValueData: """{app}\{#AppExe}"" --tray"; Flags: uninsdeletevalue; Tasks: startup

[Run]
; 1) Config + veri klasörü + başlangıç YARA kuralları.
Filename: "{app}\cli\Sentinel.Cli.exe"; Parameters: "init"; \
    Flags: runhidden waituntilterminated; StatusMsg: "Veri klasörü hazırlanıyor..."

; 2) Servisi oluştur.
Filename: "{sys}\sc.exe"; Parameters: "create {#ServiceName} binPath= ""{app}\service\Sentinel.Service.exe"" start= auto DisplayName= ""Sentinel (arka plan koruması)"""; \
    Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Servis kaydediliyor..."
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""Dosya izleme, zamanlanmış tarama ve davranış denetimi."""; \
    Flags: runhidden waituntilterminated; Tasks: service
Filename: "{sys}\sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/60000/restart/60000/restart/60000"; \
    Flags: runhidden waituntilterminated; Tasks: service
Filename: "{sys}\sc.exe"; Parameters: "start {#ServiceName}"; \
    Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Servis başlatılıyor..."

; 4) Uygulamayı aç.
Filename: "{app}\{#AppExe}"; Description: "{#AppName} uygulamasını başlat"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden waituntilterminated; RunOnceId: "KillApp"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\service"
Type: filesandordirs; Name: "{app}\cli"

[Code]
function SacState(): Integer;
var
  Value: Cardinal;
begin
  Result := -1;
  if RegQueryDWordValue(HKLM, 'SYSTEM\CurrentControlSet\Control\CI\Policy',
       'VerifiedAndReputablePolicyState', Value) then
    Result := Integer(Value);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if SacState() = 1 then
  begin
    if MsgBox('Windows 11 Akıllı Uygulama Denetimi (Smart App Control) açık.' + #13#10#13#10 +
              'Bu ayar, imzasız uygulamaları Windows Defender''dan bağımsız olarak engeller; ' +
              'Sentinel kurulduktan sonra "Uygulama Denetimi ilkesi bu dosyayı engelledi" hatası alabilirsiniz.' + #13#10#13#10 +
              'Kuruluma devam edilsin mi? (Kapatmak için: scripts\smart-app-control.ps1)',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDNO then
      Result := False;
  end;
end;

procedure StopEverything();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopEverything();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if MsgBox('Sentinel verileri de silinsin mi?' + #13#10#13#10 +
              'Karantina, olay günlüğü ve ayarlar silinir. Hayır derseniz sonraki kurulumda korunur.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\{#AppName}'), True, True, True);
  end;
end;
