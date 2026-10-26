$ErrorActionPreference = "Stop"

$hasLink = -not [string]::IsNullOrWhiteSpace($env:CSC_LINK)
$hasPassword = -not [string]::IsNullOrWhiteSpace($env:CSC_KEY_PASSWORD)

if ($hasLink -and $hasPassword) {
  Write-Host "Code signing environment is configured."
  exit 0
}

if (-not $hasLink) {
  Write-Warning "CSC_LINK is not set."
}

if (-not $hasPassword) {
  Write-Warning "CSC_KEY_PASSWORD is not set."
}

Write-Host "Production builds will be unsigned unless signing variables are provided."
