#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Helper function to toggle the Deny-Write ACL placed on the
# osqueryd parent folder for 'safe' execution on Windows.
function Set-DenyWriteAcl {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  [OutputType('System.Boolean')]
  param(
    [string] $targetDir = '',
    [string] $action = ''
  )
  if (($action -ine 'Add') -and ($action -ine 'Remove')) {
    Write-Debug '[-] Invalid action in Set-DenyWriteAcl.'
    return $false
  }
  if ($PSCmdlet.ShouldProcess($targetDir)) {
    $acl = Get-Acl $targetDir
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Deny

    $worldSIDObj = New-Object System.Security.Principal.SecurityIdentifier ('S-1-1-0')
    $worldUser = $worldSIDObj.Translate( [System.Security.Principal.NTAccount])
    $permission = $worldUser.Value, "write", $inheritanceFlag, $propagationFlag, $permType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    # We only support adding or removing the ACL
    if ($action -ieq 'add') {
      $acl.SetAccessRule($accessRule)
    }
    else {
      $acl.RemoveAccessRule($accessRule)
    }
    $acl | Set-Acl $targetDir
    return $true
  }
  return $false
}

# Helper function for running a .bat file from powershell
function Invoke-BatchFile {
  param(
    [string]$path,
    [string]$parameters
  )
  $tempFile = [IO.Path]::GetTempFileName()
  cmd.exe /c " `"$path`" $parameters && set > `"$tempFile`" "
  Get-Content $tempFile | Foreach-Object {
    if ($_ -match '^(.*?)=(.*)$') {
      Set-Content "env:\$($matches[1])" $matches[2]
    }
  }
  Remove-Item $tempFile
}

# Constructs a chocolatey .nuspec file in the current directory
function Write-NuSpec {
  param(
    [string] $packageName,
    [string] $version,
    [string] $authors,
    [string] $owners,
    [string] $projectSource,
    [string] $packageSourceUrl,
    [string] $copyright,
    [string] $license
  )
  $nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Do not remove this test for UTF-8: if “Ω” doesn’t appear as greek uppercase omega letter enclosed in quotation marks, you should use an editor that supports UTF-8, not this one. -->
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>$packageName</id>
    <title>$packageName</title>
    <version>$version</version>
    <authors>$authors</authors>
    <owners>$owners</owners>
    <summary>$packageName</summary>
    <description>$packageName</description>
    <projectUrl>$projectSource</projectUrl>
    <packageSourceUrl>$packageSourceUrl</packageSourceUrl>
    <tags>$packageName</tags>
    <copyright>$copyright</copyright>
    <licenseUrl>$license</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
  </metadata>
  <files>
    <file src="local\**" target="local" />
  </files>
</package>
"@
  Out-File -Encoding "UTF8" -FilePath "$packageName.nuspec" -InputObject $nuspec
}

# Derive the location of the osquery build location
function Get-OsqueryBuildPath {
  [OutputType('System.String')]
  param()
  $loc = Get-Location
  $toks = $loc -Split '\\'
  $ret = ''
  0..$toks.length | ForEach-Object {
    if (Test-Path "$($toks[0..$_] -Join '\')\tools\provision.ps1") {
      $ret = "$($toks[0..$_] -Join '\')\build"
    }
  }
  return $ret
}
