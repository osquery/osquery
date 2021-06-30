# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# This library file contains constant definitions and helper functions

#Requires -Version 3.0

$ErrorActionPreference = "Stop"

. (Join-Path "$PSScriptRoot" "osquery_utils.ps1")

$packageParameters = $env:chocolateyPackageParameters
$arguments = @{}

# Ensure the service is stopped and processes are not running if exists.
$svc = Get-WmiObject -ClassName Win32_Service -Filter "Name='osqueryd'"
if ($svc -and $svc.State -eq 'Running') {
  Stop-Service $serviceName
  # If we find zombie processes, ensure they're termintated
  $proc = Get-Process | Where-Object { $_.ProcessName -eq 'osqueryd' }
  if ($null -ne $proc) {
    Stop-Process -Force $proc -ErrorAction SilentlyContinue
  }
  
  # If the service was installed using the legacy path in ProgramData, remove
  # it and allow the service creation below to fix it up.
  if ([regex]::escape($svc.PathName) -like [regex]::escape("${legacyInstall}*")) {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='osqueryd'" |
    Invoke-CimMethod -MethodName Delete
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

# Install the package

# Create a log directory in case one doesn't already exist
New-Item -Force -Type directory -Path $logFolder

# Grab the primary folders
$packageRoot = (Join-Path "$PSScriptRoot" "..")
Copy-Item -Force -Recurse (Join-Path "$packageRoot" "certs") $targetFolder
Copy-Item -Force -Recurse (Join-Path "$packageRoot" "osqueryd") $targetFolder

# Grab the individual files
Copy-Item -Force (Join-Path "$packageRoot" "manage-osqueryd.ps1") $targetFolder
Copy-Item -Force (Join-Path "$packageRoot" "osquery.man") $targetFolder
Copy-Item -Force (Join-Path "$PSScriptRoot" "osquery_utils.ps1") $targetFolder
Copy-Item -Force (Join-Path "$packageRoot" "osqueryi.exe") $targetFolder

# We intentionally do not replace configuration and flags files from previous
# installations, as these often dictate the osquery configuration and may not
# change through upgrades.
$currConf = (Join-Path "$targetFolder" "osquery.conf")
if (-not (Test-Path $currConf)) {
  Copy-Item -Force (Join-Path "$packageRoot" "osquery.conf") $targetFolder
}
$currFlags = (Join-Path "$targetFolder" "osquery.flags")
if (-not (Test-Path $currFlags)) {
  Copy-Item -Force (Join-Path "$packageRoot" "osquery.flags") $targetFolder
}

# The osquery daemon requires no low privileged users have write access to run
Set-SafePermissions $daemonFolder

if ($installService) {
  if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
    Write-Debug 'Installing osquery daemon service.'
    # If the 'install' parameter is passed, we create a Windows service with
    # the flag file in the default location, 'C:\Program Files\osquery'
    $cmd = '"{0}" --flagfile="{1}\osquery.flags"' -f $destDaemonBin, $targetFolder

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
Install-ChocolateyPath $targetFolder -PathType 'Machine'
