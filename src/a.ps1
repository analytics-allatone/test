# Sentinel Agent - Windows installer (install.ps1). Run elevated.
# One-liner:
#   & ([scriptblock]::Create((irm http://YOUR_HOST/install_service.ps1))) -Name web-01 -Server 203.0.113.5

param(
  [string]$Name   = $env:AGENT_NAME,
  [string]$Server = $env:SERVER_IP
)
$ErrorActionPreference = "Stop"

if (-not $Name)   { throw "Provide -Name or set `$env:AGENT_NAME" }
if (-not $Server) { throw "Provide -Server or set `$env:SERVER_IP" }

# ---- config ----
$BaseUrl     = "https://YOUR_HOST/binaries"   # served by your FastAPI /binaries mount
$InstallDir  = "C:\SentinelAgent"
$ServiceName = "sentinel-agent"
$BinaryName  = "main.exe"                      # the file your build publishes
$ExePath     = Join-Path $InstallDir "agent.exe"

Write-Host "Installing agent '$Name' (server $Server) ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "Downloading agent..."
Invoke-WebRequest "$BaseUrl/$BinaryName" -OutFile $ExePath

@"
AGENT_NAME=$Name
SERVER_IP=$Server
"@ | Set-Content -Encoding ascii (Join-Path $InstallDir ".env")

# ---- NSSM ----
$nssm = Join-Path $InstallDir "nssm.exe"
if (-not (Test-Path $nssm)) {
  Write-Host "Downloading NSSM..."
  $zip = Join-Path $env:TEMP "nssm.zip"
  Invoke-WebRequest "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip
  Expand-Archive $zip (Join-Path $env:TEMP "nssm") -Force
  Copy-Item (Join-Path $env:TEMP "nssm\nssm-2.24\win64\nssm.exe") $nssm -Force
}

# ---- remove old service ONLY if it exists (fixes "Can't open service!") ----
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host "Removing existing service..."
  & $nssm stop   $ServiceName | Out-Null
  & $nssm remove $ServiceName confirm | Out-Null
  Start-Sleep -Seconds 2
}

# ---- install + configure ----
Write-Host "Installing service..."
& $nssm install $ServiceName $ExePath
& $nssm set $ServiceName AppDirectory $InstallDir
& $nssm set $ServiceName Start SERVICE_AUTO_START
& $nssm set $ServiceName AppExit Default Restart    # auto-restart if the agent exits

Write-Host "Starting service..."
& $nssm start $ServiceName
Start-Sleep -Seconds 3

# ---- verify ----
$svc = Get-Service -Name $ServiceName
if ($svc.Status -ne "Running") {
  Write-Error "Service did not reach Running. Current: $($svc.Status)"
  sc.exe query $ServiceName
  exit 1
}

Write-Host "Done. '$ServiceName' is $($svc.Status)."
Write-Host "Manage: Restart-Service $ServiceName  /  Stop-Service $ServiceName"