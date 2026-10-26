$ErrorActionPreference = "Stop"
npm run service:simulator
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
