<#
.SYNOPSIS
    Deploys the SecureXL Rate Limiting portal onto A-GUI and starts it.

.DESCRIPTION
    Run on A-GUI (10.1.1.201) in PowerShell:

        irm https://raw.githubusercontent.com/Don-Paterson/SecureXL-Rate-limiting/main/Deploy.ps1 | iex

    It downloads this repository, installs Python if needed (per user, no
    admin rights), builds a virtual environment with Flask and Paramiko, asks
    once for the gateway SSH credentials, adds a desktop shortcut and opens
    the portal at http://127.0.0.1:8088.

    Running it again updates the code and keeps data\ (settings and custom
    profiles).

    Optional environment variables, set before the irm line:
        $env:SXL_PATH      install folder          (default C:\SecureXL-RL)
        $env:SXL_BRANCH    git branch to deploy    (default main)
        $env:SXL_PORT      portal port             (default 8088)
        $env:SXL_SIMULATOR 1 = start in simulator mode, no gateways needed
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'      # Invoke-WebRequest is far faster without the bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo       = 'Don-Paterson/SecureXL-Rate-limiting'
$Branch     = if ($env:SXL_BRANCH) { $env:SXL_BRANCH } else { 'main' }
$InstallDir = if ($env:SXL_PATH)   { $env:SXL_PATH }   else { 'C:\SecureXL-RL' }
$Port       = if ($env:SXL_PORT)   { $env:SXL_PORT }   else { '8088' }
$Members    = @(@{ name = 'A-GW-01'; host = '10.1.1.2' }, @{ name = 'A-GW-02'; host = '10.1.1.3' })
$PyVersion  = '3.12.8'
$PyUrl      = "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-amd64.exe"

function Write-Step { param([string]$m) Write-Host "  > $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  + $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  ! $m" -ForegroundColor Yellow }

Write-Host ''
Write-Host '  ==============================================' -ForegroundColor Magenta
Write-Host '   SecureXL DoS Shield  -  A-DMZ rate limiting' -ForegroundColor White
Write-Host '  ==============================================' -ForegroundColor Magenta
Write-Host ''

# ---------------------------------------------------------------------------
# 1. Code
# ---------------------------------------------------------------------------

Write-Step "Downloading $Repo ($Branch)"
$zip     = Join-Path $env:TEMP "sxl_$([guid]::NewGuid().ToString('N')).zip"
$extract = Join-Path $env:TEMP "sxl_$([guid]::NewGuid().ToString('N'))"
Invoke-WebRequest -Uri "https://github.com/$Repo/archive/refs/heads/$Branch.zip" -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $extract -Force
$src = Get-ChildItem $extract -Directory | Select-Object -First 1

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
# Copy everything except data\, so settings and custom profiles survive updates.
Get-ChildItem $src.FullName -Force | Where-Object { $_.Name -ne 'data' } | ForEach-Object {
    Copy-Item $_.FullName -Destination $InstallDir -Recurse -Force
}
Remove-Item $zip, $extract -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'data') -Force | Out-Null
Write-Ok "Code in $InstallDir"

# ---------------------------------------------------------------------------
# 2. Python
# ---------------------------------------------------------------------------

function Find-Python {
    # The WindowsApps python.exe is a Store redirect stub, not an interpreter.
    $candidates = @()
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        try { $candidates += (& py -3 -c "import sys; print(sys.executable)" 2>$null) } catch { }
    }
    $candidates += (Get-Command python -All -ErrorAction SilentlyContinue | ForEach-Object Source)
    $candidates += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName
    $candidates += Get-ChildItem "C:\Program Files\Python3*\python.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName

    foreach ($c in $candidates | Where-Object { $_ -and $_ -notmatch 'WindowsApps' } | Select-Object -Unique) {
        try {
            $v = & $c -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($v -and [version]$v -ge [version]'3.9') { return $c }
        } catch { }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Step "Python not found - installing Python $PyVersion for this user"
    $installer = Join-Path $env:TEMP "python-$PyVersion-amd64.exe"
    Invoke-WebRequest -Uri $PyUrl -OutFile $installer -UseBasicParsing
    $p = Start-Process -FilePath $installer -Wait -PassThru -ArgumentList @(
        '/quiet', 'InstallAllUsers=0', 'PrependPath=1', 'Include_launcher=0', 'Include_test=0', 'Shortcuts=0')
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne 0) { throw "Python installer failed with exit code $($p.ExitCode)" }
    $python = Find-Python
    if (-not $python) { throw 'Python installed but could not be located. Open a new PowerShell window and re-run.' }
}
Write-Ok "Python: $python"

# ---------------------------------------------------------------------------
# 3. Virtual environment
# ---------------------------------------------------------------------------

$venv   = Join-Path $InstallDir '.venv'
$venvPy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Write-Step 'Creating virtual environment'
    & $python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'python -m venv failed' }
}
Write-Step 'Installing Flask and Paramiko'
& $venvPy -m pip install --quiet --disable-pip-version-check --upgrade pip 2>$null | Out-Null
& $venvPy -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed - check internet access from A-GUI' }
Write-Ok 'Dependencies ready'

# ---------------------------------------------------------------------------
# 4. Settings (first run only)
# ---------------------------------------------------------------------------

$settingsFile = Join-Path $InstallDir 'data\settings.json'
$simulator    = $env:SXL_SIMULATOR -eq '1'

if (-not (Test-Path $settingsFile)) {
    Write-Host ''
    Write-Host '  Gateway SSH access (Expert / bash shell user on A-GW-01 and A-GW-02)' -ForegroundColor White
    $user = Read-Host '  SSH user [admin]'
    if (-not $user) { $user = 'admin' }
    $secure = Read-Host '  SSH password (blank = set it later in the portal)' -AsSecureString
    $plain  = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))

    [pscustomobject]@{
        members      = $Members
        ssh_user     = $user
        ssh_password = $plain
        ssh_port     = 22
        dmz_ip       = '192.168.12.101'
        lab_prefix   = 'ADMZ-'
        simulator    = $simulator
        commands     = @{}
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $settingsFile -Encoding UTF8
    $plain = $null
    Write-Ok 'Settings saved (data\settings.json - lab use only, password is stored in plain text)'
}
else {
    Write-Ok 'Keeping existing settings'
}

foreach ($m in $Members) {
    $ok = Test-NetConnection -ComputerName $m.host -Port 22 -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($ok) { Write-Ok "$($m.name) ($($m.host)) answers on SSH" }
    else     { Write-Warn "$($m.name) ($($m.host)) not reachable on TCP 22 - check Gaia SSH / the policy" }
}

# ---------------------------------------------------------------------------
# 5. Launcher, shortcut, start
# ---------------------------------------------------------------------------

$launcher = Join-Path $InstallDir 'Start-Portal.cmd'
$simFlag  = if ($simulator) { ' --simulator' } else { '' }
@"
@echo off
title SecureXL DoS Shield portal
cd /d "$InstallDir\portal"
"$venvPy" app.py --port $Port$simFlag
"@ | Set-Content -Path $launcher -Encoding ASCII

try {
    $desktop  = [Environment]::GetFolderPath('Desktop')
    $shell    = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $desktop 'SecureXL DoS Shield.lnk'))
    $shortcut.TargetPath       = $launcher
    $shortcut.WorkingDirectory = Join-Path $InstallDir 'portal'
    $shortcut.IconLocation     = "$env:SystemRoot\System32\imageres.dll,101"
    $shortcut.WindowStyle      = 7
    $shortcut.Save()
    Write-Ok 'Desktop shortcut: SecureXL DoS Shield'
}
catch { Write-Warn "Could not create the desktop shortcut: $($_.Exception.Message)" }

# Stop an older copy still holding the port.
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.OwningProcess -Force } catch { }
}

Start-Process -FilePath $launcher -WindowStyle Minimized
Write-Host ''
Write-Ok "Portal starting at http://127.0.0.1:$Port/  (browser opens automatically)"
Write-Host "    Restart it any time from the desktop shortcut or $launcher" -ForegroundColor Gray
Write-Host ''
