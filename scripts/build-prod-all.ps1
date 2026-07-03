$ErrorActionPreference = "Stop"
$env:SHADOW_SSH_BUILD_CHANNEL = "production"
$env:NODE_ENV = "production"
npm run build:prod-all
