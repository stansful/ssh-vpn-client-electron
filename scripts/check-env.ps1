$ErrorActionPreference = "Stop"

function Require-Command {
  param([string]$Name)
  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $command) {
    throw "Required command '$Name' was not found in PATH."
  }
  return $command.Source
}

$node = Require-Command "node"
$npm = Require-Command "npm"
$nodeVersion = (& node --version)
if ($LASTEXITCODE -ne 0) { throw "Unable to query the Node.js version." }
$npmVersion = (& npm --version)
if ($LASTEXITCODE -ne 0) { throw "Unable to query the npm version." }
$os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

Write-Host "Node: $nodeVersion ($node)"
Write-Host "npm:  $npmVersion ($npm)"
Write-Host "OS:   $os"
Write-Host "Arch: $arch"

$parsedNodeVersion = [Version]($nodeVersion.TrimStart("v").Split("-")[0])
$nodeSupported = (($parsedNodeVersion.Major -eq 22) -and ($parsedNodeVersion -ge [Version]"22.12.0")) -or ($parsedNodeVersion.Major -ge 24)
if (-not $nodeSupported) {
  throw "Node.js 22.12+ (22.x) or Node.js 24+ is required; found $nodeVersion."
}

$parsedNpmVersion = [Version]($npmVersion.Split("-")[0])
if ($parsedNpmVersion -lt [Version]"10.0.0") {
  throw "npm 10+ is required; found $npmVersion."
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
  Write-Warning "Windows EXE builds should be produced on Windows for service and signing validation."
}
