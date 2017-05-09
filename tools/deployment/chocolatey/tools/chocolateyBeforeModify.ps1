#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
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
