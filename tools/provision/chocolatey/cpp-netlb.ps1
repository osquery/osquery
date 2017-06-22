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
$version = '0.12.0-r3'
$chocoVersion = $version
$packageName = 'cpp-netlib'
$projectSource = 'https://github.com/poppyseedplehzr/cpp-netlib/tree/win-osquery-build'
$packageSourceUrl = 'https://github.com/poppyseedplehzr/cpp-netlib/tree/win-osquery-build'
$authors = 'cpp-netlib'
$owners = 'cpp-netlib'
$copyright = 'https://github.com/cpp-netlib/cpp-netlib/blob/master/LICENSE_1_0.txt'
$license = 'https://github.com/cpp-netlib/cpp-netlib/blob/master/LICENSE_1_0.txt'

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

$chocolateyRoot = "C:\ProgramData\chocolatey\lib"
$openSslDir = "$chocolateyRoot\openssl"
$openSslInclude = "$openSslDir\include"
$boostRoot = "$chocolateyRoot\boost-msvc14\local"
$boostLibRoot = "$boostRoot\lib64-msvc-14.0"
$env:OPENSSL_ROOT_DIR = $openSslDir
$env:BOOST_ROOT = $boostRoot
$env:BOOST_LIBRARYDIR = $boostLibRoot

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

# Checkout our working, patched, build of cpp-netlib 0.12-final
git clone https://github.com/poppyseedplehzr/cpp-netlib.git
$sourceDir = 'cpp-netlib'
Set-Location $sourceDir
git submodule update --init
git checkout win-osquery-build

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

# Generate the .sln
cmake -G 'Visual Studio 14 2015 Win64' -DCPP-NETLIB_BUILD_TESTS=OFF -DCPP-NETLIB_BUILD_EXAMPLES=OFF -DCPP-NETLIB_BUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DBOOST_ROOT=C:\ProgramData\chocolatey\lib\boost-msvc14\local -DBOOST_LIBRARYDIR=C:\ProgramData\chocolatey\lib\boost-msvc14\local\lib64-msvc-14.0 -DOPENSSL_INCLUDE_DIR=C:\ProgramData\chocolatey\lib\openssl\local\include -DOPENSSL_ROOT_DIR=C:\ProgramData\chocolatey\lib\openssl\local ..\

# Build the libraries
msbuild 'cpp-netlib.sln' /p:Configuration=Release /m /t:ALL_BUILD /v:m
msbuild 'cpp-netlib.sln' /p:Configuration=Debug /m /t:ALL_BUILD /v:m

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

# Rename the Debug libraries to end with a `_dbg.lib`
foreach ($lib in Get-ChildItem "$buildDir\libs\network\src\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\libs\network\src\Release\*" $libDir
Copy-Item -Recurse "$buildDir\..\boost" $includeDir
Copy-Item -Recurse "$buildDir\..\deps\asio\asio\include\asio" $includeDir
Copy-Item "$buildDir\..\deps\asio\asio\include\asio.hpp" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
