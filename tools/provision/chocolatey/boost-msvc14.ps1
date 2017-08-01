#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# For more information -
# https://studiofreya.com/2016/09/29/how-to-build-boost-1-62-with-visual-studio-2015/
# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package
$version = '1.63.0'
$chocoVersion = '1.63.0'
$packageName = 'boost-msvc14'
$projectSource = 'http://www.boost.org/users/history/version_1_63_0.html'
$packageSourceUrl = 'http://www.boost.org/users/history/version_1_63_0.html'
$authors = 'boost-msvc14'
$owners = 'boost-msvc14'
$copyright = 'http://www.boost.org/users/license.html'
$license = 'http://www.boost.org/users/license.html'
$versionUnderscores = $version -replace '\.', '_'
$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
$url = "http://downloads.sourceforge.net/project/boost/boost/$version/boost_$versionUnderscores.7z?r=&ts=$timestamp&use_mirror=pilotfiber"

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

# Retrieve the source
Invoke-WebRequest $url -OutFile "boost-$version.7z" -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

# Extract the source
7z x "boost-$version.7z"
Set-Location "boost_$versionUnderscores"
$sourceDir = Get-Location

# Build the libraries
Invoke-BatchFile './bootstrap.bat'
.\b2.exe -j2 toolset=msvc-14.0 address-model=64 architecture=x86 link=static threading=multi runtime-link=static --build-type=minimal stage --stagedir=stage/x64
.\b2.exe -j2 toolset=msvc-14.0 address-model=32 architecture=x86 link=static threading=multi runtime-link=static --build-type=minimal stage --stagedir=stage/win32

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

Copy-Item "$sourceDir\stage\x64\lib\*" $libDir
Copy-Item -Recurse "$sourceDir\boost" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
