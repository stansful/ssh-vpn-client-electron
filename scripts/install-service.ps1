$ErrorActionPreference = "Stop"

$serviceName = $env:SHADOW_SSH_SERVICE_NAME
if (-not $serviceName) { $serviceName = "ShadowSshService" }

$serviceExe = $env:SHADOW_SSH_SERVICE_EXE
if (-not $serviceExe) {
  $serviceExe = Join-Path (Resolve-Path ".").Path "native\windows\x64\shadow-ssh-service.exe"
}

$serviceEndpoint = $env:SHADOW_SSH_SERVICE_ENDPOINT
if (-not $serviceEndpoint) {
  $serviceEndpoint = "\\.\pipe\shadow-ssh-service"
}

if (-not (Test-Path $serviceExe)) {
  throw "Service executable not found: $serviceExe"
}

$binPath = "`"$serviceExe`" --service --endpoint `"$serviceEndpoint`""

sc.exe create $serviceName binPath= $binPath start= demand DisplayName= "Shadow SSH Service"
sc.exe description $serviceName "Privileged routing and SSH tunnel service for Shadow SSH."
Write-Host "Installed service $serviceName from $binPath"
