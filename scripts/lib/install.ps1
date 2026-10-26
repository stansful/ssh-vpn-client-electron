$ErrorActionPreference = "Stop"
& "$PSScriptRoot/check-env.ps1"
npm install
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
