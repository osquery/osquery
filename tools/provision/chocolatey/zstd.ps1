#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1.2.0'
$chocoVersion = '1.2.0-r1'
$packageName = 'zstd'
$projectSource = 'https://github.com/facebook/zstd'
$packageSourceUrl = 'https://github.com/facebook/zstd'
$authors = 'Facebook'
$owners = 'Facebook'
$copyright = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$license = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$url = "https://github.com/facebook/zstd/archive/v$version.zip"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Create the choco build dir if needed
$buildPath = Get-OsqueryBuildPath
if ($buildPath -eq '') {
  Write-Host '[-] Failed to find source root' -foregroundcolor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# Retreive the source
Invoke-WebRequest $url -OutFile "$packageName-$version.zip"

# Extract the source
7z x "$packageName-$version.zip"
$sourceDir = "$packageName-$version"
Set-Location $sourceDir

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

# Rename the Debug libraries to end with a `_dbg.lib`
#foreach ($lib in Get-ChildItem "$buildDir\libs\network\src\Debug\") {
#  $toks = $lib.Name.split('.')
#  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
#  $suffix = $toks[$($toks.count - 1)]
#  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
#}
Copy-Item "$sourceDir\static\*" $libDir
Copy-Item -Recurse "$sourceDir\include\*" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
