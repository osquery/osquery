#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package
# Note: not currently used as @poppyseedplehzr maintains our working branch
$version = '0.12.0-r4'
$chocoVersion = $version
$packageName = 'cpp-netlib'
$projectSource = 'https://github.com/poppyseedplehzr/' +
                 'cpp-netlib/tree/win-osquery-build'
$packageSourceUrl = 'https://github.com/poppyseedplehzr/' +
                    'cpp-netlib/tree/win-osquery-build'
$authors = 'cpp-netlib'
$owners = 'cpp-netlib'
$copyright = 'https://github.com/cpp-netlib/cpp-netlib/blob/' +
             'master/LICENSE_1_0.txt'
$license = 'https://github.com/cpp-netlib/cpp-netlib/blob/' +
           'master/LICENSE_1_0.txt'

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

# Checkout our working, patched, build of cpp-netlib 0.12-final
git clone https://github.com/poppyseedplehzr/cpp-netlib.git
$sourceDir = 'cpp-netlib'
Set-Location $sourceDir
git submodule update --init
git checkout win-osquery-build

# Build the libraries, remove any old versions first.
$buildDir = Join-Path $(Get-Location) 'osquery-win-build'
if(Test-Path $buildDir){
  Remove-Item -Force -Recurse $buildDir
}
New-Item -Force -ItemType Directory -Path $buildDir
Set-Location $buildDir

# Generate the .sln
# Boost Static Libs - 06e23a7d34ead324d45b00d60bdfa9d0acb9bc2c
$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  '-G "Visual Studio 14 2015 Win64"',
  '-DCPP-NETLIB_BUILD_TESTS=OFF',
  '-DCPP-NETLIB_BUILD_EXAMPLES=OFF',
  '-DCPP-NETLIB_BUILD_SHARED_LIBS=OFF',
  '-DCMAKE_BUILD_TYPE=Release',
  '-DCPP-NETLIB_STATIC_BOOST=ON',
  "-DBOOST_ROOT=$boostRoot",
  "-DBOOST_LIBRARYDIR=$boostLibRoot",
  "-DOPENSSL_INCLUDE_DIR=$openSslInclude",
  "-DOPENSSL_ROOT_DIR=$openSslRoot",
  '..\'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$msbuildArgs = @(
  'cpp-netlib.sln',
  '/p:Configuration=Release',
  '/t:ALL_BUILD',
  '/m',
  '/v:m'
)
Start-OsqueryProcess $msbuild $msbuildArgs

$msbuildArgs = @(
  'cpp-netlib.sln',
  '/p:Configuration=Debug',
  '/t:ALL_BUILD',
  '/m',
  '/v:m'
)
Start-OsqueryProcess $msbuild $msbuildArgs

# If the build path exists, purge it for a clean packaging
$chocoDir = Join-Path $(Get-Location) 'osquery-choco'
if (Test-Path $chocoDir) {
  Remove-Item -Force -Recurse $chocoDir
}

# Construct the Chocolatey Package
New-Item -ItemType Directory -Path $chocoDir
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
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

# Rename the Debug libraries to end with a `_dbg.lib`
foreach ($lib in Get-ChildItem "$buildDir\libs\network\src\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item `
    -Path $lib.Fullname `
    -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\libs\network\src\Release\*" $libDir
Copy-Item -Recurse "$buildDir\..\boost" $includeDir
Copy-Item -Recurse "$buildDir\..\deps\asio\asio\include\asio" $includeDir
Copy-Item "$buildDir\..\deps\asio\asio\include\asio.hpp" $includeDir
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
