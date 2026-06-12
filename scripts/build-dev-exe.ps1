$ErrorActionPreference = "Stop"
$env:SHADOW_SSH_BUILD_CHANNEL = "development"
$env:NODE_ENV = "development"
npm run build:dev-exe
