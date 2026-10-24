$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location (Join-Path $Root "demo")
Write-Host "Open http://localhost:8000/login.html"
& (Join-Path $Root ".venv\Scripts\python.exe") -m http.server 8000 --bind 127.0.0.1
