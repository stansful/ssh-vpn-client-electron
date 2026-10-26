$ErrorActionPreference = "Stop"
npm run dev
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
