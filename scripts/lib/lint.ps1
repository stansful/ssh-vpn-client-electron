$ErrorActionPreference = "Stop"
npm run lint
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
