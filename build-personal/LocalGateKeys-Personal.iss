#define AppName "LocalGateKeys"
#define AppVersion "0.4.0-personal"

; Template. scripts\build_personal_installer.ps1 rewrites the relative paths
; below into absolute ones and writes the result to
; build-personal\LocalGateKeys-Personal.generated.iss, so this file stays portable.

[Setup]
AppId={{31F3995E-BE92-4AF6-AD15-73F835E67ED7}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\LocalGateKeys
; Always this per-user folder: a folder chosen elsewhere (e.g. directly under the system drive, where
; Authenticated Users may modify) would let another account replace the app or
; the native host the browser starts, and [UninstallDelete] would wipe a chosen
; existing folder. [Code] below also refuses /DIR= and any other location.
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=LocalGateKeys
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=
OutputDir=..\dist-installer
OutputBaseFilename=LocalGateKeys-Setup-Personal
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\icons\localgatekeys.ico
UninstallDisplayIcon={app}\LocalGateKeys.exe
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes

[InstallDelete]
; Both PyInstaller runtimes are replaced as a whole on every install, so files
; older versions shipped and this one does not (old *.dist-info folders such as
; cryptography-50.0.1.dist-info, the Tk runtime of the old UI, the native
; host's former Tk/Pillow/TLS/asyncio modules) never linger. Nothing user-owned
; lives here: profiles and settings are under %LOCALAPPDATA%\LocalGateKeys, and
; PrepareToInstall stops both processes first.
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\NativeHost\_internal"

[Files]
Source: "..\dist-personal\LocalGateKeys\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist-personal\LocalGateKeysNativeHost\*"; DestDir: "{app}\NativeHost"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\browser-extension\*"; DestDir: "{app}\browser-extension"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\LocalGateKeys"; Filename: "{app}\LocalGateKeys.exe"; IconFilename: "{app}\assets\icons\localgatekeys.ico"
Name: "{userdesktop}\LocalGateKeys"; Filename: "{app}\LocalGateKeys.exe"; IconFilename: "{app}\assets\icons\localgatekeys.ico"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "LocalGateKeys"; ValueData: """{app}\LocalGateKeys.exe"""; Flags: uninsdeletevalue
; localgatekeys://install-licence/ links from the licence page open the app, which verifies and asks first.
Root: HKCU; Subkey: "Software\Classes\localgatekeys"; ValueType: string; ValueName: ""; ValueData: "URL:LocalGateKeys"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\localgatekeys"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\localgatekeys\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: """{app}\LocalGateKeys.exe"",0"
Root: HKCU; Subkey: "Software\Classes\localgatekeys\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\LocalGateKeys.exe"" ""%1"""

[Run]
Filename: "{app}\LocalGateKeys.exe"; Parameters: "--repair-browser-bridge"; Flags: runhidden waituntilterminated
Filename: "{app}\LocalGateKeys.exe"; Description: "Start LocalGateKeys"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\LocalGateKeys.exe"; Parameters: "--unregister-browser-bridge"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "LocalGateKeysRemoveUserBrowserBridge"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
// LocalGateKeys keeps running in the tray, so the Restart Manager cannot close
// it (closing the window only hides it). Stop this user's copies explicitly
// before files are replaced. The vault is written atomically, so ending the
// process only locks it.

function IsProcessRunning(const ExeName: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if Exec(ExpandConstant('{cmd}'),
      '/C tasklist /NH /FI "IMAGENAME eq ' + ExeName + '" /FI "USERNAME eq ' + GetUserNameString + '" | find /I "' + ExeName + '" >NUL',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := (ResultCode = 0);
end;

procedure StopProcess(const ExeName: String);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'),
    '/F /T /FI "USERNAME eq ' + GetUserNameString + '" /IM ' + ExeName,
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function StopLocalGateKeys(): Boolean;
var
  Attempt: Integer;
begin
  StopProcess('LocalGateKeys.exe');
  StopProcess('LocalGateKeysNativeHost.exe');
  for Attempt := 1 to 20 do
  begin
    if (not IsProcessRunning('LocalGateKeys.exe')) and (not IsProcessRunning('LocalGateKeysNativeHost.exe')) then
    begin
      Result := True;
      exit;
    end;
    Sleep(250);
  end;
  Result := False;
end;

// The only accepted install folder (see DisableDirPage above). Compared as text,
// case-insensitively; a different spelling of the same folder (8.3 names, a
// junction) is refused too, which fails safe.
function DefaultAppDir(): String;
begin
  Result := ExpandConstant('{localappdata}\Programs\LocalGateKeys');
end;

function IsAllowedAppDir(const Dir: String): Boolean;
begin
  Result := (Pos('..', Dir) = 0) and
    (CompareText(RemoveBackslashUnlessRoot(Dir), RemoveBackslashUnlessRoot(DefaultAppDir())) = 0);
end;

function AppDirRefusal(const Dir: String): String;
begin
  Result := 'LocalGateKeys can only be installed in ' + DefaultAppDir() + '.' + #13#10 + #13#10 +
    'Setup refused: ' + Dir;
end;

function InitializeSetup(): Boolean;
var
  RequestedDir: String;
begin
  Result := True;
  // /DIR= on the command line (DisableDirPage does not stop it).
  RequestedDir := ExpandConstant('{param:DIR|}');
  if (RequestedDir <> '') and (not IsAllowedAppDir(RequestedDir)) then
  begin
    SuppressibleMsgBox(AppDirRefusal(RequestedDir), mbCriticalError, MB_OK, IDOK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // Final gate on the resolved {app}, whatever set it (wizard, /DIR=, /LOADINF=).
  // NextButtonClick is not used: it never runs for the disabled directory page.
  if not IsAllowedAppDir(ExpandConstant('{app}')) then
  begin
    Result := AppDirRefusal(ExpandConstant('{app}'));
    exit;
  end;
  if IsProcessRunning('LocalGateKeys.exe') then
  begin
    if (not WizardSilent) and
       (MsgBox('LocalGateKeys is running. Setup will close it so it can be updated.' + #13#10 + #13#10 +
               'Your vault is saved on this device and will be locked. Continue?',
               mbConfirmation, MB_OKCANCEL) <> IDOK) then
    begin
      Result := 'Setup was cancelled because LocalGateKeys is still running.';
      exit;
    end;
  end;
  if not StopLocalGateKeys() then
    Result := 'LocalGateKeys could not be closed. Exit it from its tray icon and run Setup again.';
end;

function InitializeUninstall(): Boolean;
begin
  StopLocalGateKeys();
  Result := True;
end;
