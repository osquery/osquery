$progData =  [System.Environment]::GetEnvironmentVariable('ProgramData')
$targetFolder = Join-Path $progData "osquery"
$serviceName = 'osqueryd'

# Remove the osquery path from the System PATH variable. Note: Here
# we don't make use of our local vars, as Regex requires escaping the '\'
$oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($oldPath -imatch [regex]::escape($targetFolder)) {
  $newPath = $oldPath -replace [regex]::escape($targetFolder),$NULL
  [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}

if ((Get-Service $serviceName -ErrorAction SilentlyContinue)) {
  Stop-Service $serviceName
  Set-Service $serviceName -startuptype 'manual'
  Get-CimInstance -ClassName Win32_Service -Filter "Name='osqueryd'" | Invoke-CimMethod -methodName Delete
}

if (Test-Path $targetFolder) {
  Remove-Item -Force -Recurse $targetFolder
  if (Test-Path $targetFolder) {
    Write-Output 'osquery uninstallation was unsuccessful.'
  } else {
    Write-Output 'osquery was uninstalled successfully.'
  }
} else {
  Write-Output 'osquery was not found on the system. Nothing to do.'
}
