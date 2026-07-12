$ErrorActionPreference = "Stop"

$serviceName = $env:SHADOW_SSH_SERVICE_NAME
if (-not $serviceName) { $serviceName = "ShadowSshService" }

$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::StopPending) {
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(25))
}
if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
  Start-Service -Name $serviceName -ErrorAction Stop
}
if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
}
Write-Host "Started service $serviceName"
