# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# This library file contains constant definitions and helper functions

#Requires -Version 3.0

. (Join-Path "$PSScriptRoot" "osquery_utils.ps1")

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
