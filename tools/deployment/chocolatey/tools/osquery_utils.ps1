#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

# Force Powershell to use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# The osquery installation happens in Program Files
$progFiles =  [System.Environment]::GetEnvironmentVariable('ProgramFiles')
$targetFolder = Join-Path $progFiles 'osquery'

# Maintain the daemon and extension folders for "safe" permissions management
$daemonFolder = Join-Path $targetFolder 'osqueryd'
$extensionsFolder = Join-Path $targetFolder 'extensions'
$logFolder = Join-Path $targetFolder 'log'

# Maintain the binary paths for creating the system service and extraction
$targetDaemonBin = Join-Path $targetFolder "osqueryd.exe"
$destDaemonBin = Join-Path $daemonFolder "osqueryd.exe"

# Meta data for the system service installation
$serviceName = 'osqueryd'
$serviceDescription = 'osquery daemon service'

# Track the old installation paths for removal
$progData = [System.Environment]::GetEnvironmentVariable('ProgramData')
$legacyInstall = Join-Path $progData "osquery"

# Helper function to add an explicit Deny-Write ACE for the Everyone group
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
    $worldUser = $worldSIDObj.Translate([System.Security.Principal.NTAccount])
    $permission = $worldUser.Value, "write", $inheritanceFlag, $propagationFlag, $permType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    # We only support adding or removing the ACL
    if ($action -ieq 'add') {
      $acl.SetAccessRule($accessRule)
    } else {
      $acl.RemoveAccessRule($accessRule)
    }
    Set-Acl $targetDir $acl
    return $true
  }
  return $false
}

# A helper function to set "safe" permissions for osquery binaries
function Set-SafePermissions {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  [OutputType('System.Boolean')]
  param(
    [string] $target = ''
  )
  if ($PSCmdlet.ShouldProcess($target)) {
    $acl = Get-Acl $target

    # First, to ensure success, we remove the entirety of the ACL
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($access in $acl.Access) {
      $acl.RemoveAccessRule($access)
    }
    Set-Acl $target $acl

    $acl = Get-Acl $target
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Allow

    # "Safe" permissions in osquery entail the containing folder and binary both
    # are owned by the Administrators group, as well as no account has Write
    # permissions except for the Administrators group and SYSTEM account
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $systemUser = $systemSid.Translate([System.Security.Principal.NTAccount])

    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $adminsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])

    $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $usersGroup = $usersSid.Translate([System.Security.Principal.NTAccount])

    $permGroups = @($systemUser, $adminsGroup, $usersGroup)
    foreach ($accnt in $permGroups) {
      $grantedPerm = ''
      if ($accnt -eq $usersGroup) {
        $grantedPerm = 'ReadAndExecute'
      } else {
        $grantedPerm = 'FullControl'
      }
      $permission = $accnt.Value, $grantedPerm, $inheritanceFlag, $propagationFlag, $permType
      $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
      $acl.SetAccessRule($accessRule)
    }
    $acl.SetOwner($adminsGroup)
    Set-Acl $target $acl

    # Finally set the Administrators group as the owner for all items
    $items = Get-ChildItem -Recurse -Path $target
    foreach ($item in $items) {
      $acl = Get-Acl -Path $item.FullName
      $acl.SetOwner($adminsGroup)
      Set-Acl $item.FullName $acl
    }

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

# Helper function to add to the SYSTEM path
function Add-ToSystemPath {
  param(
    [string] $targetFolder = ''
  )

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
}

# A helper function for starting and waiting on processes in powershell
function Start-OsqueryProcess {
  param(
    [string] $binaryPath = '',
    [array] $binaryArgs = @(),
    [bool] $redirectOutput = $true
  )
  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  $pinfo.FileName = $binaryPath
  $pinfo.RedirectStandardError = $redirectOutput
  $pinfo.RedirectStandardOutput = $redirectOutput
  $pinfo.UseShellExecute = $false
  $pinfo.Arguments = $binaryArgs
  $pinfo.WorkingDirectory = Get-Location
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $pinfo
  $p.Start()
  $p.WaitForExit()

  if ($redirectOutput) {
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $exit = $p.ExitCode
    [PSCustomObject] @{
      stdout = $stdout
      stderr = $stderr
      exitcode = $exit
    }
  } else {
    $exit = $p.ExitCode
    [PSCustomObject] @{
      exitcode = $exit
    }
  }
}

# A helper function to derive the latest VS install
function Get-VSInfo {

  # Attempt to make use of vswhere to derive the build tools scripts
  $vswhere = (Get-Command 'vswhere').Source
  $vswhereArgs = @('-latest', '-legacy')
  $vswhereOut = (Start-OsqueryProcess $vswhere $vswhereArgs).stdout
  $vsinfo = New-Object -TypeName psobject
  $vsinfo | Add-Member -MemberType NoteProperty -Name version -Value ''
  $vsinfo | Add-Member -MemberType NoteProperty -Name location -Value ''
  foreach ($l in $vswhereOut.split([environment]::NewLine)) {
    $toks = $l.split(":")
    if ($toks.Length -lt 2) {
      continue
    }
    if ($toks[0].trim() -like 'installationVersion') {
      $vsinfo.version = $toks[1].Split(".")[0]
    }
    if ($toks[0].trim() -like 'installationPath') {
      $vsinfo.location = [System.String]::Join(":", $toks[1..$toks.Length])
    }
  }
  $vsinfo.location = $vsinfo.location.trim()
  $vsinfo.version = $vsinfo.version.trim()
  return $vsinfo
}

# A helper function to derive the latest VS install and call vcvarsall.bat
function Invoke-VcVarsAll {
  $vsinfo = Get-VSInfo
  $vsLoc = $vsinfo.location
  $vsVersion = $vsinfo.version

  if ($vsLoc -ne '') {
    $vcvarsall = Join-Path $vsLoc 'VC'
    if ($vsVersion -eq '15') {
      $vcvarsall = Join-Path $vcvarsall '\Auxiliary\Build\vcvarsall.bat'
    } else {
      $vcvarsall = Join-Path $vcvarsall 'vcvarsall.bat'
    }

    # Lastly invoke the environment provisioning script
    $null = Invoke-BatchFile "$vcvarsall" "amd64"
    return $true
  }

  # As a last ditch effort, attempt to find the env variables set by VS2015
  # in order to derive the location of vcvarsall
  $vsComnTools = [environment]::GetEnvironmentVariable("VS140COMNTOOLS")
  if ($vsComnTools -eq '') {
    return $false
  }
  $vcvarsall = Resolve-Path $(Join-Path "$vsComnTools" "..\..\VC")
  $vcvarsall = Join-Path $vcvarsall 'vcvarsall.bat'
  $null = Invoke-BatchFile "$vcvarsall" "amd64"
  return $true
}
