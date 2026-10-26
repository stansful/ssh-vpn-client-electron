$ErrorActionPreference = "Stop"
$env:SHADOW_SSH_BUILD_CHANNEL = "production"
$env:NODE_ENV = "production"
npm run build:portable-all
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
