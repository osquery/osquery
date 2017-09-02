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
# Note: not currently used as @poppyseedplehzr maintains our working branch
$version = '111.0'
$chocoVersion = $version
$packageName = 'beast'
$projectSource = 'https://github.com/boostorg/beast/tree/master'
$packageSourceUrl = 'https://github.com/boostorg/beast/tree/master'

$authors = 'beast'
$owners = 'beast'
$copyright = 'https://github.com/boostorg/beast/blob/master/LICENSE_1_0.txt'
$license = 'https://github.com/boostorg/beast/blob/master/LICENSE_1_0.txt'

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

$chocolateyRoot = 'C:\ProgramData\chocolatey\lib'
$openSslRoot = "$chocolateyRoot\openssl\local"
$openSslInclude = "$openSslRoot\include"
$boostRoot = "$chocolateyRoot\boost-msvc14\local"
$boostLibRoot = "$boostRoot\lib"
$env:OPENSSL_ROOT_DIR = $openSslRoot
$env:BOOST_ROOT = $boostRoot
$env:BOOST_LIBRARYDIR = $boostLibRoot

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Create the choco build dir if needed
$buildPath = Get-OsqueryBuildPath
if ($buildPath -eq '') {
  Write-Host '[-] Failed to find source root' -ForegroundColor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# Checkout our working, patched, build of beast-v111
git clone https://github.com/uptycs-nishant/beast.git
$sourceDir = 'beast'
Set-Location $sourceDir
git checkout v111

# Build the libraries, remove any old versions first.
$buildDir = Join-Path $(Get-Location) 'osquery-win-build'
if(Test-Path $buildDir){
  Remove-Item -Force -Recurse $buildDir
}
New-Item -Force -ItemType Directory -Path $buildDir
Set-Location $buildDir

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

Copy-Item -Recurse "$buildDir\..\include\boost" $includeDir
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
