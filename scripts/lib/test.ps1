$ErrorActionPreference = "Stop"
npm run test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
