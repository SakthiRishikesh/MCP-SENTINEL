$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Project virtualenv not found. Create it with: py -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e '.[dev]'"
}
$env:PATH = (Split-Path -Parent $python) + [IO.Path]::PathSeparator + $env:PATH

# Run the control plane on Windows so local stdio MCP servers can see Windows paths.
# Keep its state outside the source tree; an empty Redis URL selects the built-in local store.
$state = Join-Path $env:LOCALAPPDATA "MCP-Sentinel"
New-Item -ItemType Directory -Force -Path $state | Out-Null
$stateUrl = ([IO.Path]::GetFullPath($state)).Replace('\', '/')
$repoUrl = $repo.Replace('\', '/')
$env:SENTINEL_DATABASE_URL = "sqlite:///$stateUrl/sentinel.db"
$env:SENTINEL_REDIS_URL = ""
$env:SENTINEL_GATEWAY_HOST = "127.0.0.1"
$env:SENTINEL_GATEWAY_PORT = "8443"
$env:SENTINEL_PUBLIC_URL = "http://localhost:8443"
$env:SENTINEL_DASHBOARD_URL = "http://localhost:8443"
$env:SENTINEL_ALLOWED_HOSTS = "localhost,127.0.0.1,::1"
$env:SENTINEL_CORS_ORIGINS = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"
$env:SENTINEL_STATIC_DASHBOARD_DIR = "$repoUrl/dashboard/dist"
$env:SENTINEL_STATIC_WEB_DIR = "$repoUrl/web/dist"
$env:SENTINEL_SECRETS_KEY_FILE = "$stateUrl/keys/sentinel.key"
$env:SENTINEL_RECEIPT_KEY_FILE = "$stateUrl/keys/receipt_ed25519.pem"

Write-Host "Starting MCP-Sentinel natively on Windows at http://localhost:8443"
Write-Host "Dashboard: http://localhost:8443/app/"
Write-Host "State: $state"
& $python -m sentinel.cli serve
exit $LASTEXITCODE
