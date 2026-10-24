$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Source = Join-Path $Root "demo\LocalVaultDesktopDemo.cs"
$OutputDir = Join-Path $env:LOCALAPPDATA "LocalVaultPrototype\demo"
$Exe = Join-Path $OutputDir "LocalVaultDesktopDemo.exe"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if (-not (Test-Path $Exe) -or (Get-Item $Source).LastWriteTimeUtc -gt (Get-Item $Exe).LastWriteTimeUtc) {
    Remove-Item -Force -ErrorAction SilentlyContinue $Exe
    Add-Type `
        -Path $Source `
        -ReferencedAssemblies @("System.Windows.Forms", "System.Drawing") `
        -OutputAssembly $Exe `
        -OutputType WindowsApplication
}

Write-Host "Starting the local desktop login demo: $Exe"
& $Exe
