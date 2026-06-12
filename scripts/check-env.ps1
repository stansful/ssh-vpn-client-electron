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
$npmVersion = (& npm --version)
$os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

Write-Host "Node: $nodeVersion ($node)"
Write-Host "npm:  $npmVersion ($npm)"
Write-Host "OS:   $os"
Write-Host "Arch: $arch"

if (-not $nodeVersion.StartsWith("v20") -and -not $nodeVersion.StartsWith("v22") -and -not $nodeVersion.StartsWith("v24")) {
  Write-Warning "Node 20, 22, or 24 is recommended."
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
  Write-Warning "Windows EXE builds should be produced on Windows for service and signing validation."
}
