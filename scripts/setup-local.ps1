$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$apiRoot = Join-Path $projectRoot "api"
$runtimeRoot = Join-Path $env:LOCALAPPDATA "ClassTrack\runtime"
$nodeDirectory = Join-Path $runtimeRoot "node-v24.22.1-win-x64"
$postgresDirectory = Join-Path $runtimeRoot "postgresql-18.6\pgsql"
$postgresBin = Join-Path $postgresDirectory "bin"
$dataDirectory = Join-Path $runtimeRoot "postgres-data"
$envPath = Join-Path $apiRoot ".env"

$node = Join-Path $nodeDirectory "node.exe"
$npm = Join-Path $nodeDirectory "npm.cmd"
$initdb = Join-Path $postgresBin "initdb.exe"
$pgCtl = Join-Path $postgresBin "pg_ctl.exe"
$psql = Join-Path $postgresBin "psql.exe"

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $node)) {
  $archive = Join-Path $runtimeRoot "node-v24.22.1-win-x64.zip"
  Invoke-WebRequest -Uri "https://nodejs.org/dist/v24.22.1/node-v24.22.1-win-x64.zip" -OutFile $archive
  $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne "d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5") {
    throw "Node.js portable archive SHA-256 verification failed."
  }
  Expand-Archive -LiteralPath $archive -DestinationPath $runtimeRoot -Force
}

if (-not (Test-Path -LiteralPath $initdb)) {
  $archive = Join-Path $runtimeRoot "postgresql-18.6-5-windows-x64-binaries.zip"
  Invoke-WebRequest -Uri "https://get.enterprisedb.com/postgresql/postgresql-18.6-5-windows-x64-binaries.zip" -OutFile $archive
  $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne "e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2") {
    throw "PostgreSQL portable archive SHA-256 verification failed."
  }
  $postgresExtract = Join-Path $runtimeRoot "postgresql-18.6"
  New-Item -ItemType Directory -Path $postgresExtract -Force | Out-Null
  Expand-Archive -LiteralPath $archive -DestinationPath $postgresExtract -Force
}

foreach ($path in @($node, $npm, $initdb, $pgCtl, $psql)) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Required portable runtime is missing: $path. Install Node.js and PostgreSQL binaries first."
  }
}

$environment = @{}
if (Test-Path -LiteralPath $envPath) {
  foreach ($line in Get-Content -LiteralPath $envPath) {
    if ($line -match "^([^#=]+)=(.*)$") {
      $environment[$matches[1]] = $matches[2]
    }
  }
}

function New-Secret {
  $bytes = New-Object byte[] 32
  $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $generator.GetBytes($bytes)
  } finally {
    $generator.Dispose()
  }
  return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if (-not $environment.ContainsKey("POSTGRES_SUPERUSER_PASSWORD")) {
  $environment["POSTGRES_SUPERUSER_PASSWORD"] = New-Secret
}
if (-not $environment.ContainsKey("DATABASE_PASSWORD")) {
  $environment["DATABASE_PASSWORD"] = New-Secret
}
if (-not $environment.ContainsKey("BOOTSTRAP_TEACHER_PASSWORD")) {
  $environment["BOOTSTRAP_TEACHER_PASSWORD"] = New-Secret
}
if ($environment["BOOTSTRAP_TEACHER_PASSWORD"] -eq "change-this-password") {
  $environment["BOOTSTRAP_TEACHER_PASSWORD"] = New-Secret
}
if (-not $environment.ContainsKey("NODE_ENV")) { $environment["NODE_ENV"] = "development" }
if (-not $environment.ContainsKey("PORT")) { $environment["PORT"] = "3000" }
if (-not $environment.ContainsKey("APP_ORIGIN")) { $environment["APP_ORIGIN"] = "http://localhost:3000" }
if (-not $environment.ContainsKey("BOOTSTRAP_TEACHER_USERNAME")) {
  $environment["BOOTSTRAP_TEACHER_USERNAME"] = if ($environment.ContainsKey("BOOTSTRAP_TEACHER_EMAIL")) { $environment["BOOTSTRAP_TEACHER_EMAIL"].Split("@")[0] } else { "teacher" }
}

$environment["DATABASE_URL"] = "postgres://classtrack:$($environment['DATABASE_PASSWORD'])@127.0.0.1:5432/classtrack"
$environmentText = ($environment.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
[System.IO.File]::WriteAllText($envPath, "$environmentText`n", [System.Text.UTF8Encoding]::new($false))

$env:PATH = "$postgresBin;$nodeDirectory;$env:PATH"
$dataDirectoryExists = Test-Path -LiteralPath (Join-Path $dataDirectory "PG_VERSION")
if (-not $dataDirectoryExists) {
  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  $passwordFile = Join-Path $runtimeRoot "postgres-init-password.txt"
  try {
    [System.IO.File]::WriteAllText($passwordFile, $environment["POSTGRES_SUPERUSER_PASSWORD"], [System.Text.UTF8Encoding]::new($false))
    & $initdb -D $dataDirectory -U postgres --auth-local=scram-sha-256 --auth-host=scram-sha-256 --encoding=UTF8 --no-locale "--pwfile=$passwordFile"
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL initdb failed with exit code $LASTEXITCODE." }
  } finally {
    if (Test-Path -LiteralPath $passwordFile) {
      Remove-Item -LiteralPath $passwordFile -Force
    }
  }
}

& $pgCtl -D $dataDirectory status *> $null
if ($LASTEXITCODE -ne 0) {
  $logPath = Join-Path $runtimeRoot "postgresql.log"
  & $pgCtl -D $dataDirectory -l $logPath -o "-h 127.0.0.1 -p 5432" start -w
  if ($LASTEXITCODE -ne 0) { throw "PostgreSQL failed to start. Inspect $logPath." }
}

$env:PGPASSWORD = $environment["POSTGRES_SUPERUSER_PASSWORD"]
$existingRole = & $psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'classtrack'"
if ($LASTEXITCODE -ne 0) { throw "Could not connect to the local PostgreSQL server." }
$rolePassword = $environment["DATABASE_PASSWORD"]
if (($existingRole | Out-String).Trim() -eq "1") {
  & $psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "ALTER ROLE classtrack WITH LOGIN PASSWORD '$rolePassword'"
} else {
  & $psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE classtrack LOGIN PASSWORD '$rolePassword'"
}
if ($LASTEXITCODE -ne 0) { throw "Could not configure the ClassTrack database user." }

$existingDatabase = & $psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'classtrack'"
if ($LASTEXITCODE -ne 0) { throw "Could not check whether the ClassTrack database exists." }
if (($existingDatabase | Out-String).Trim() -ne "1") {
  & (Join-Path $postgresBin "createdb.exe") -h 127.0.0.1 -p 5432 -U postgres -O classtrack classtrack
  if ($LASTEXITCODE -ne 0) { throw "Could not create the ClassTrack database." }
}
$env:PGPASSWORD = $environment["DATABASE_PASSWORD"]

Push-Location $apiRoot
try {
  & $npm install
  if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE." }
  & $npm run db:migrate
  if ($LASTEXITCODE -ne 0) { throw "Database migration failed with exit code $LASTEXITCODE." }
  & $npm run db:seed
  if ($LASTEXITCODE -ne 0) { throw "Database seeding failed with exit code $LASTEXITCODE." }
} finally {
  Pop-Location
}

Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
Write-Host "ClassTrack local setup completed."
Write-Host "Teacher login: $($environment['BOOTSTRAP_TEACHER_USERNAME'])"
Write-Host "Teacher password: $($environment['BOOTSTRAP_TEACHER_PASSWORD'])"
Write-Host "Start the website with .\scripts\start-local.ps1"
