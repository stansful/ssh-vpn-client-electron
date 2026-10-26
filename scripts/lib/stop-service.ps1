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
  # Native routing rollback may use two bounded five-second attempts and wait
  # for one in-flight mutation, so do not claim success while SCM is pending.
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(25))
}
Write-Host "Stopped service $serviceName"
