$ErrorActionPreference = "Stop"

$serviceName = $env:SHADOW_SSH_SERVICE_NAME
if (-not $serviceName) { $serviceName = "ShadowSshService" }

$serviceExe = $env:SHADOW_SSH_SERVICE_EXE
if (-not $serviceExe) {
  $runtimeArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  if ($runtimeArch -eq "arm64") {
    $serviceArch = "arm64"
  } elseif ($runtimeArch -eq "x64") {
    $serviceArch = "x64"
  } else {
    throw "Unsupported Windows service architecture: $runtimeArch. Set SHADOW_SSH_SERVICE_EXE explicitly to override."
  }
  $serviceExe = Join-Path (Resolve-Path ".").Path "native\windows\$serviceArch\shadow-ssh-service.exe"
}

$serviceEndpoint = $env:SHADOW_SSH_SERVICE_ENDPOINT
if (-not $serviceEndpoint) {
  $serviceEndpoint = "\\.\pipe\shadow-ssh-service"
}

$allowedClientSid = $env:SHADOW_SSH_ALLOWED_CLIENT_SID
if (-not $allowedClientSid) {
  $allowedClientSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
if (-not $allowedClientSid) {
  throw "Unable to determine the Windows SID for the desktop user."
}

if (-not (Test-Path $serviceExe)) {
  throw "Service executable not found: $serviceExe"
}

$binPath = "`"$serviceExe`" --service --endpoint `"$serviceEndpoint`" --allowed-client-sid `"$allowedClientSid`""

sc.exe create $serviceName binPath= $binPath start= demand DisplayName= "Shadow SSH Service"
if ($LASTEXITCODE -ne 0) {
  throw "sc.exe create failed for $serviceName with exit code $LASTEXITCODE."
}
sc.exe description $serviceName "Privileged routing and SSH tunnel service for Shadow SSH."
if ($LASTEXITCODE -ne 0) {
  # Do not report a fully configured install when the description/configuration
  # step failed. The created service remains visible for explicit repair/removal.
  throw "sc.exe description failed for $serviceName with exit code $LASTEXITCODE."
}
Write-Host "Installed service $serviceName from $binPath"
