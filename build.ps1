$ErrorActionPreference = "Stop"

if (-not (Test-Path "assets/npcap-installer.exe")) {
    Write-Error "assets/npcap-installer.exe not found. Download Npcap first."
    exit 1
}

Write-Host "Building isis-attack.exe..."
pyinstaller --clean --noconfirm isis-attack.spec
Write-Host "Done: dist/isis-attack.exe"
