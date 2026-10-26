$ErrorActionPreference = "Stop"
npm run clean
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
