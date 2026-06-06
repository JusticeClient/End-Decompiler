#define AppName "End Decompiler"
#define AppVer "1.0.0"
#define AppExe "End Decompiler.exe"
#define Publisher "End Decompiler"

[Setup]
AppId={{8F2C5A41-3E7B-4C9D-9A2E-7D1B6F0A4E93}
AppName={#AppName}
AppVersion={#AppVer}
AppVerName={#AppName} {#AppVer}
AppPublisher={#Publisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=no
DisableWelcomePage=no
AllowNoIcons=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=output
OutputBaseFilename=EndDecompiler-{#AppVer}-Setup
SetupIconFile=icon.ico
WizardImageFile=wizard-large.bmp
WizardSmallImageFile=wizard-small.bmp
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
VersionInfoVersion={#AppVer}
VersionInfoProductName={#AppName}
VersionInfoCompany={#Publisher}
AppContact=
CloseApplications=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\src-tauri\target\release\endecompiler.exe"; DestDir: "{app}"; DestName: "{#AppExe}"; Flags: ignoreversion
Source: "..\src-tauri\resources\*"; DestDir: "{app}\resources"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "VclStylesinno.dll"; Flags: dontcopy
Source: "Carbon.vsf"; Flags: dontcopy

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Installing the WebView2 runtime..."; Check: WebView2Missing; Flags: waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
procedure LoadVCLStyle(VClStyleFile: String); external 'LoadVCLStyleW@files:VclStylesinno.dll stdcall setuponly';
procedure UnLoadVCLStyles; external 'UnLoadVCLStyles@files:VclStylesinno.dll stdcall setuponly';

var
  StyleLoaded: Boolean;

procedure InitializeWizard();
begin
  ExtractTemporaryFile('Carbon.vsf');
  LoadVCLStyle(ExpandConstant('{tmp}\Carbon.vsf'));
  StyleLoaded := True;
end;

procedure DeinitializeSetup();
begin
  if StyleLoaded then
    UnLoadVCLStyles();
end;

function WebView2Missing(): Boolean;
var
  v: String;
begin
  Result := not (
    RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', v) or
    RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', v) or
    RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', v)
  );
end;
