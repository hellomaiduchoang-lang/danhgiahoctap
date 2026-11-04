$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$apiRoot = Join-Path $projectRoot "api"
$runtimeRoot = Join-Path $env:LOCALAPPDATA "ClassTrack\runtime"
$nodeDirectory = Join-Path $runtimeRoot "node-v24.22.1-win-x64"
$postgresDirectory = Join-Path $runtimeRoot "postgresql-18.6\pgsql"
$postgresBin = Join-Path $postgresDirectory "bin"
$dataDirectory = Join-Path $runtimeRoot "postgres-data"
$logPath = Join-Path $env:TEMP "ClassTrack-postgresql.log"
$node = Join-Path $nodeDirectory "node.exe"
$npm = Join-Path $nodeDirectory "npm.cmd"
$pgCtl = Join-Path $postgresBin "pg_ctl.exe"
$pgIsReady = Join-Path $postgresBin "pg_isready.exe"
$envPath = Join-Path $apiRoot ".env"

foreach ($path in @($node, $npm, $pgCtl, $pgIsReady, $envPath)) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "ClassTrack is not set up yet. Run .\scripts\setup-local.ps1 first. Missing: $path"
  }
}

function Test-PostgresReady {
  & $pgIsReady -h 127.0.0.1 -p 5432 *> $null
  return $LASTEXITCODE -eq 0
}

function Wait-ForPostgres {
  param([int]$TimeoutSeconds)

  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  do {
    if (Test-PostgresReady) { return $true }
    Start-Sleep -Seconds 1
  } while ([DateTime]::UtcNow -lt $deadline)
  return $false
}

function Ensure-PostgresReady {
  & $pgCtl -D $dataDirectory status *> $null
  $serverRunning = $LASTEXITCODE -eq 0

  if ($serverRunning -and -not (Wait-ForPostgres -TimeoutSeconds 5)) {
    Write-Host "PostgreSQL is running but not accepting connections. Restarting it safely..."
    & $pgCtl -D $dataDirectory stop -m fast -w -t 15
    if ($LASTEXITCODE -ne 0) {
      throw "PostgreSQL did not stop cleanly. Inspect $logPath before retrying."
    }
    $serverRunning = $false
  }

  if (-not $serverRunning) {
    & $pgCtl -D $dataDirectory -l $logPath -o "-h 127.0.0.1 -p 5432" start -w
    if ($LASTEXITCODE -ne 0) {
      throw "PostgreSQL failed to start. Inspect $logPath."
    }
  }

  if (-not (Wait-ForPostgres -TimeoutSeconds 30)) {
    throw "PostgreSQL did not accept connections within 30 seconds. Inspect $logPath."
  }
}

function Test-ClassTrackHealth {
  try {
    $health = Invoke-RestMethod -Uri "$address/api/health" -TimeoutSec 2
    $sessionStatus = $null
    try {
      $null = Invoke-WebRequest -Uri "$address/api/session" -TimeoutSec 2 -UseBasicParsing
      $sessionStatus = 200
    } catch {
      if ($_.Exception.Response) { $sessionStatus = [int]$_.Exception.Response.StatusCode }
    }
    return $health.status -eq "ok" -and $sessionStatus -in @(401, 403)
  } catch {
    return $false
  }
}

# Keep one predictable address. If the port is already serving ClassTrack, use
# that server; if another process owns it, stop with instructions instead of
# silently starting on a different address that could cause API 404s.
$configuredPort = 3000
$portLine = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^\s*PORT\s*=' } | Select-Object -Last 1
if ($portLine -and $portLine -match '^\s*PORT\s*=\s*(\d+)') {
  $configuredPort = [int]$Matches[1]
}
$address = "http://127.0.0.1:$configuredPort"
$portProbe = [System.Net.Sockets.TcpClient]::new()
try {
  $connection = $portProbe.BeginConnect([System.Net.IPAddress]::Loopback, $configuredPort, $null, $null)
  $portIsOpen = $connection.AsyncWaitHandle.WaitOne(500)
  if ($portIsOpen) {
    try { $portProbe.EndConnect($connection) } catch { $portIsOpen = $false }
  }
} finally {
  $portProbe.Dispose()
}
if ($portIsOpen) {
  if (Test-ClassTrackHealth) {
    Write-Host "ClassTrack is already running at $address. Open that address; no second server was started."
    exit 0
  }

  $isClassTrack = $false
  try {
    $page = Invoke-WebRequest -Uri "$address/" -TimeoutSec 2 -UseBasicParsing
    $isClassTrack = $page.StatusCode -eq 200 -and $page.Content.Contains("ClassTrack")
  } catch {
    $isClassTrack = $false
  }
  if ($isClassTrack) {
    Ensure-PostgresReady
    if (Test-ClassTrackHealth) {
      Write-Host "ClassTrack recovered its database connection and is running at $address."
      exit 0
    }
  }
  throw "Port $configuredPort is in use by a different or outdated server. Stop that process, then run .\scripts\start-local.ps1 again."
}

Ensure-PostgresReady
$env:PORT = [string]$configuredPort
$env:APP_ORIGIN = $address

$env:PATH = "$postgresBin;$nodeDirectory;$env:PATH"
Set-Location -LiteralPath $apiRoot
Write-Host "ClassTrack will open at $($env:APP_ORIGIN). Press Ctrl+C to stop the web server."
& $npm start
if ($LASTEXITCODE -ne 0) { throw "ClassTrack API exited with code $LASTEXITCODE." }
