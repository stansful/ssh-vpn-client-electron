$ErrorActionPreference = "Stop"

$serviceName = $env:SHADOW_SSH_SERVICE_NAME
if (-not $serviceName) { $serviceName = "ShadowSshService" }

$service = Get-Service -Name $serviceName -ErrorAction Stop
if (
  $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped -and
  $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::StopPending
) {
  Stop-Service -Name $serviceName -ErrorAction Stop
}
if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(25))
}
sc.exe delete $serviceName
if ($LASTEXITCODE -ne 0) {
  throw "sc.exe delete failed for $serviceName with exit code $LASTEXITCODE."
}
Write-Host "Uninstalled service $serviceName"
