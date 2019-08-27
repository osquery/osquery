#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

# This library file contains constant definitions and helper functions

#Requires -Version 3.0

. "$PSScriptRoot\\osquery_utils.ps1"

$packageParameters = $env:chocolateyPackageParameters
$arguments = @{}

# Ensure the service is stopped and processes are not running if exists.
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -and `
  (Get-Service $serviceName).Status -eq 'Running') {
  Stop-Service $serviceName
  # If we find zombie processes, ensure they're termintated
  $proc = Get-Process | Where-Object { $_.ProcessName -eq 'osqueryd' }
  if ($null -ne $proc) {
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
Set-SafePermissions $daemonFolder

if ($installService) {
  if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
    Write-Debug 'Installing osquery daemon service.'
    # If the 'install' parameter is passed, we create a Windows service with
    # the flag file in the default location in \Program Files\osquery\
    # the flag file in the default location in Program Files
    $cmd = '"{0}" --flagfile="C:\Program Files\osquery\osquery.flags"' -f $destDaemonBin

    $svcArgs = @{
      Name = $serviceName
      BinaryPathName = $cmd
      DisplayName = $serviceName
      Description = $serviceDescription
      StartupType = "Automatic"
    }
    New-Service @svcArgs

    # If the osquery.flags file doesn't exist, we create a blank one.
    if (-not (Test-Path "$targetFolder\osquery.flags")) {
      Add-Content "$targetFolder\osquery.flags" $null
    }
  }
  Start-Service $serviceName
}

# Add osquery binary path to machines path for ease of use.
Add-ToSystemPath $targetFolder
