$ErrorActionPreference = "Stop"

$serviceName = $env:SHADOW_SSH_SERVICE_NAME
if (-not $serviceName) { $serviceName = "ShadowSshService" }

sc.exe start $serviceName
