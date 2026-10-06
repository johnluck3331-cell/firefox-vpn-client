# build-windows.ps1 - Build FoxyVPN Windows binaries from source.
# Run on Windows 11 in PowerShell (as a normal user; no admin needed to build).
# Prerequisite: Go 1.25+ installed (https://go.dev/dl/)

$ErrorActionPreference = "Stop"
$env:GOOS   = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

if (Test-Path out) { Remove-Item -Recurse -Force out }
New-Item -ItemType Directory -Path out | Out-Null

Write-Host "[1/3] go vet ..."
go vet ./...

Write-Host "[2/3] Building foxyvpn-proxy.exe (SOCKS5 demo, ready to use today) ..."
go build -trimpath -ldflags "-s -w" -o out\foxyvpn-proxy.exe .\cmd\proxy-demo

Write-Host "[3/3] Done. Binaries are in .\out\"
Get-ChildItem out
