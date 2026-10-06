# FoxyVPN on Windows 11 — Quick Start

Currently the working end-to-end binary is **foxyvpn-proxy** (Firefox VPN over an
HTTP/2 CONNECT tunnel, exposed as a local SOCKS5 proxy on 127.0.0.1:1080).
The Wintun/Netstack system-wide VPN layer is implemented but not yet runtime-verified.

## Build & run on Windows
1. Install Git and Go 1.25+ (https://go.dev/dl/, https://git-scm.com/download/win).
2. Clone repo, open PowerShell in the repo folder.
3. `powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1`
4. `.\out\foxyvpn-proxy.exe -print-info` → login with your Firefox account.
5. `.\out\foxyvpn-proxy.exe -country DE` → SOCKS5 proxy on 127.0.0.1:1080.
See docs/WINDOWS-INSTALL-FA.md for the full step-by-step guide (Persian).
