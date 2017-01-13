. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\\osquery_utils.ps1"

$serviceName = 'osqueryd'
$progData =  [System.Environment]::GetEnvironmentVariable('ProgramData')
$targetFolder = Join-Path $progData "osquery"
$daemonFolder = Join-Path $targetFolder $serviceName

# Before modifying we ensure to stop the service, if it exists
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -and (Get-Service $serviceName).Status -eq 'Running') {
  Stop-Service $serviceName
}

# Lastly, ensure that the Deny Write ACLs have been removed before modifying
if (Test-Path $daemonFolder) {
  Set-DenyWriteAcl $daemonFolder 'Remove'
}
