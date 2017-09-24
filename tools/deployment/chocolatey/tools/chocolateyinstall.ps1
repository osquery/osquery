#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\\osquery_utils.ps1"

$serviceName = 'osqueryd'
$serviceDescription = 'osquery daemon service'
$progData = [System.Environment]::GetEnvironmentVariable('ProgramData')
$targetFolder = Join-Path $progData 'osquery'
$daemonFolder = Join-Path $targetFolder 'osqueryd'
$extensionsFolder = Join-Path $targetFolder 'extensions'
$logFolder = Join-Path $targetFolder 'log'
$targetDaemonBin = Join-Path $targetFolder 'osqueryd.exe'
$destDaemonBin = Join-Path $daemonFolder 'osqueryd.exe'
$packageParameters = $env:chocolateyPackageParameters
$arguments = @{}

# Ensure the service is stopped and processes are not running if exists.
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -and `
  (Get-Service $serviceName).Status -eq 'Running') {
  Stop-Service $serviceName
  # If we find zombie processes, ensure they're termintated
  $proc = Get-Process | Where-Object { $_.ProcessName -eq 'osqueryd' }
  if ($proc -ne $null) {
    Stop-Process -Force $proc -ErrorAction SilentlyContinue
  }
}

# Lastly, ensure that the Deny Write ACLs have been removed before modifying
if (Test-Path $daemonFolder) {
  Set-DenyWriteAcl $daemonFolder 'Remove'
}
if (Test-Path $extensionsFolder) {
  Set-DenyWriteAcl $extensionsFolder 'Remove'
}

# Now parse the packageParameters using good old regular expression
if ($packageParameters) {
  $match_pattern = "\/(?<option>([a-zA-Z]+)):(?<value>([`"'])?([a-zA-Z0-9- _\\:\.]+)([`"'])?)|\/(?<option>([a-zA-Z]+))"
  $option_name = 'option'
  $value_name = 'value'

  if ($packageParameters -match $match_pattern ) {
    $results = $packageParameters | Select-String $match_pattern -AllMatches
    $results.matches | ForEach-Object {
      $arguments.Add(
        $_.Groups[$option_name].Value.Trim(),
        $_.Groups[$value_name].Value.Trim())
    }
  } else {
    Throw "Package Parameters were found but were invalid (REGEX Failure)"
  }
  if ($arguments.ContainsKey("InstallService")) {
    $installService = $true
  }
} else {
  Write-Debug "No Package Parameters Passed in"
}

New-Item -Force -Type directory -Path $daemonFolder
New-Item -Force -Type directory -Path $logFolder
$packagePath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\\bin\\osquery.zip"
Get-ChocolateyUnzip -FileFullPath $packagePath -Destination $targetFolder

# In order to run osqueryd as a service, we need to have a folder that has a
# Deny Write ACL to everyone.
Move-Item -Force -Path $targetDaemonBin -Destination $destDaemonBin
Set-DenyWriteAcl $daemonFolder 'Add'

if ($installService) {
  if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
    Write-Debug 'Installing osquery daemon service.'
    # If the 'install' parameter is passed, we create a Windows service with
    # the flag file in the default location in \ProgramData\osquery\
    New-Service -Name $serviceName -BinaryPathName "$destDaemonBin --flagfile=\ProgramData\osquery\osquery.flags" -DisplayName $serviceName -Description $serviceDescription -StartupType Automatic

    # If the osquery.flags file doesn't exist, we create a blank one.
    if (-not (Test-Path "$targetFolder\osquery.flags")) {
      Add-Content "$targetFolder\osquery.flags" $null
    }
  }
  Start-Service $serviceName
}

# Add osquery binary path to machines path for ease of use.
$oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if (-not ($oldPath -imatch [regex]::escape($targetFolder))) {
  $newPath = $oldPath
  if ($oldPath[-1] -eq ';') {
    $newPath = $newPath + $targetFolder
  } else {
    $newPath = $newPath + ';' + $targetFolder
  }
  [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}
