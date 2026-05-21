# ================================
# Sentinel Agent Windows Installer
# install.ps1
# Run as Administrator
# ================================

# Stop on errors
$ErrorActionPreference = "Stop"

Write-Host "====================================="
Write-Host " Sentinel Agent Installer"
Write-Host "====================================="
# Python installer URL
$PythonInstaller = "$env:TEMP\python-installer.exe"

$PythonDownloadUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"



# -----------------------------
# CONFIG
# -----------------------------
$ServiceName = "sentinel-agent"

$InstallDir = $PSScriptRoot
Write-Host "$InstallDir"
$PythonVersion = "3.12"

$NSSMDir = "$InstallDir"
# NSSM ZIP
$NSSMZip = "$InstallDir\nssm.zip"

$NSSMExe = "$NSSMDir\nssm-2.24\win64\nssm.exe"

$MainModule = "main"

# Change if requirements file differs
$RequirementsFile = "requirements.txt"

# -----------------------------
# CHECK ADMIN
# -----------------------------
$currentUser = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $currentUser.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run PowerShell as Administrator."
    exit 1
}

Write-Host "[+] Running as Administrator"

# -----------------------------
# CREATE INSTALL DIRECTORY
# -----------------------------
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

Write-Host "[+] Install directory ready"

# -----------------------------
# COPY CURRENT PROJECT
# -----------------------------
Write-Host "[+] Copying project files..."

$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$InstallDir = "C:\SentinelAgent"

if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

robocopy $SourceDir $InstallDir /E

Write-Host "[+] Files copied"

# -----------------------------
# CHECK PYTHON
# -----------------------------
# -----------------------------
# CHECK / INSTALL PYTHON
# -----------------------------
Write-Host "[+] Checking Python..."

$PythonPath = $null

try {
    $PythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
catch {
    Write-Warning "Python not found."
}

if (-not $PythonPath) {

    Write-Host "[+] Downloading Python $PythonVersion..."

    Invoke-WebRequest `
        -Uri $PythonDownloadUrl `
        -OutFile $PythonInstaller

    Write-Host "[+] Installing Python silently..."

    Start-Process `
        -FilePath $PythonInstaller `
        -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" `
        -Wait

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable(
        "Path",
        [System.EnvironmentVariableTarget]::Machine
    )

    Start-Sleep -Seconds 5

    try {
        $PythonPath = (Get-Command python).Source
    }
    catch {
        Write-Error "Python installation failed."
        exit 1
    }
}

Write-Host "[+] Python found:"
Write-Host $PythonPath

# -----------------------------
# CREATE VENV
# -----------------------------
$VenvDir = "$InstallDir\.venv"

if (!(Test-Path $VenvDir)) {

    Write-Host "[+] Creating virtual environment..."

    & $PythonPath -m venv $VenvDir
}

$VenvPython = "$VenvDir\Scripts\python.exe"

# -----------------------------
# UPGRADE PIP
# -----------------------------
Write-Host "[+] Upgrading pip..."

& $VenvPython -m pip install --upgrade pip

# -----------------------------
# INSTALL REQUIREMENTS
# -----------------------------
$ReqPath = "$InstallDir\$RequirementsFile"

if (Test-Path $ReqPath) {

    Write-Host "[+] Installing dependencies..."

    & $VenvPython -m pip install -r $ReqPath
}
else {

    Write-Warning "requirements.txt not found"
}

# -----------------------------
# CHECK NSSM
# -----------------------------
$Urls = @(
    "https://nssm.cc/ci/nssm-2.24-103-gdee49fc.zip",
    "https://nssm.cc/release/nssm-2.24.zip"
)

$Downloaded = $false

foreach ($Url in $Urls) {

    try {

        Write-Host "[+] Trying: $Url"

        Invoke-WebRequest `
            -Uri $Url `
            -OutFile $NSSMZip

        $Downloaded = $true

        Write-Host "[+] NSSM downloaded"

        break
    }
    catch {

        Write-Warning "Failed: $Url"
    }
}

if (-not $Downloaded) {

    Write-Error "Unable to download NSSM."
    exit 1
}

# -----------------------------
# CHECK / EXTRACT NSSM
# -----------------------------
Write-Host "[+] Checking NSSM..."

if (!(Test-Path $NSSMExe)) {

    if (Test-Path $NSSMZip) {

        Write-Host "[+] Extracting NSSM..."

        Expand-Archive `
            -Path $NSSMZip `
            -DestinationPath $NSSMDir `
            -Force

        # NSSM ZIP usually extracts into:
        # nssm-2.24\win64\nssm.exe

        $ExtractedExe = Get-ChildItem `
            -Path $NSSMDir `
            -Recurse `
            -Filter nssm.exe |
            Where-Object { $_.FullName -match "win64" } |
            Select-Object -First 1

        if ($ExtractedExe) {

            $NSSMExe = $ExtractedExe.FullName
        }
        else {

            Write-Error "nssm.exe not found after extraction."
            exit 1
        }
    }
    else {

        Write-Error "NSSM ZIP not found:"
        Write-Host $NSSMZip
        exit 1
    }
}

Write-Host "[+] NSSM ready:"
Write-Host $NSSMExe
# -----------------------------
# REMOVE OLD SERVICE
# -----------------------------
$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($ExistingService) {

    Write-Host "[+] Removing old service..."

    & $NSSMExe stop $ServiceName | Out-Null

    & $NSSMExe remove $ServiceName confirm | Out-Null

    Start-Sleep -Seconds 2
}

# -----------------------------
# INSTALL SERVICE
# -----------------------------
Write-Host "[+] Installing Windows service..."

& $NSSMExe install $ServiceName `
    $VenvPython `
    "-m $MainModule"

& $NSSMExe set $ServiceName AppExit Default Restart
# -----------------------------
# SERVICE CONFIG
# -----------------------------
Write-Host "[+] Configuring service..."

& $NSSMExe set $ServiceName AppDirectory $InstallDir

& $NSSMExe set $ServiceName Start SERVICE_AUTO_START

# & $NSSMExe set $ServiceName AppStdout "$InstallDir\logs\stdout.log"

# & $NSSMExe set $ServiceName AppStderr "$InstallDir\logs\stderr.log"

# & $NSSMExe set $ServiceName AppRotateFiles 1

# & $NSSMExe set $ServiceName AppRotateOnline 1

# -----------------------------
# CREATE LOG DIR
# -----------------------------
# $LogDir = "$InstallDir\logs"

# if (!(Test-Path $LogDir)) {

#     New-Item -ItemType Directory -Path $LogDir | Out-Null
# }

# -----------------------------
# START SERVICE
# -----------------------------
Write-Host "[+] Starting service..."

& $NSSMExe start $ServiceName

Start-Sleep -Seconds 3

# -----------------------------
# VERIFY
# -----------------------------
$Service = Get-Service -Name $ServiceName
if ($Service.Status -ne "Running") {
    Write-Error "Service failed to start."
    # Get-Content "$InstallDir\logs\stderr.log" -Tail 50
    sc.exe query $ServiceName
    exit 1
}

Write-Host ""
Write-Host "====================================="
Write-Host " INSTALL COMPLETE"
Write-Host "====================================="
Write-Host ""

Write-Host "Service Status:"
Write-Host $Service.Status

Write-Host ""
Write-Host "Install Directory:"
Write-Host $InstallDir

Write-Host ""
Write-Host "Logs:"
Write-Host "$InstallDir\logs"

Write-Host ""
Write-Host "Useful Commands:"
Write-Host "-----------------------------------"

Write-Host "Get-Service $ServiceName"

Write-Host "sc query $ServiceName"

Write-Host "Restart-Service $ServiceName"

Write-Host "Stop-Service $ServiceName"

Write-Host ""

Write-Host "====================================="