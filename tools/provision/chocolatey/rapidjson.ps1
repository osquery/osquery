#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package
$version = '1.1.0'
$chocoVersion = '1.1.0'
$packageName = 'rapidjson'
$projectSource = 'https://github.com/miloyip/rapidjson/'
$packageSourceUrl = 'https://github.com/miloyip/rapidjson/'
$authors = 'Tencent'
$owners = 'Tencent'
$copyright = 'Copyright (C) 2015 THL A29 Limited, a Tencent company, ' +
             'and Milo Yip. All rights reserved.'
$license = 'https://raw.githubusercontent.com/miloyip/rapidjson/master/' +
           'license.txt'
$url = "https://github.com/miloyip/rapidjson/archive/v$version.zip"

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
if (-not (Test-Path "$packageName-$version.zip")) {
  Invoke-WebRequest $url -OutFile "$packageName-$version.zip"
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "$packageName-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $arg = "x $packageName-$version.zip"
  Start-Process -FilePath $7z -ArgumentList $arg -NoNewWindow -Wait
}
Set-Location $sourceDir

# If the build path exists, purge it for a clean packaging
$chocoDir = Join-Path $(Get-Location) 'osquery-choco'
if (Test-Path $chocoDir) {
  Remove-Item -Force -Recurse $chocoDir
}

# Construct the Chocolatey Package
New-Item -ItemType Directory -Path $chocoDir
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license

Copy-Item -Recurse "$buildDir\..\include\rapidjson" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host `
    "[+] Finished building $packageName v$chocoVersion." `
    -ForegroundColor Green
}
else {
  Write-Host `
    "[-] Failed to build $packageName v$chocoVersion." `
    -ForegroundColor Red
}