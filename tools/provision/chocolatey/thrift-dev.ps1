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
$version = '0.10.0'
$chocoVersion = '0.10.0-r3'
$packageName = 'thrift-dev'
$projectSource = 'https://github.com/apache/thrift'
$packageSourceUrl = 'https://github.com/apache/thrift'
$authors = 'thrift-dev'
$owners = 'thrift-dev'
$copyright = 'https://github.com/apache/thrift/blob/master/LICENSE'
$license = 'https://github.com/apache/thrift/blob/master/LICENSE'
$url = "https://github.com/apache/thrift/archive/$version.zip"

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
$sourceDir = Join-Path $(Get-Location) "thrift-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x $packageName-$version.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

# Patches are applied in this section before build
# Windows TPipe implementations are _very_ noisy, so we squelch the output
Add-Content `
  -NoNewline `
  -Path "$buildDir\..\lib\cpp\CMakeLists.txt" `
  -Value "`nadd_definitions(-DTHRIFT_SQUELCH_CONSOLE_OUTPUT=1)"

# Generate the solution files
$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  '-G "Visual Studio 14 2015 Win64"',
  '-DBUILD_COMPILER=ON',
  '-DWITH_SHARED_LIB=OFF',
  '-DBUILD_TESTING=OFF',
  '-DBUILD_TUTORIALS=OFF',
  '-DWITH_ZLIB=ON',
  '-DZLIB_INCLUDE_DIR=C:/ProgramData/chocolatey/lib/zlib/local/include',
  '-DZLIB_LIBRARY=C:/ProgramData/chocolatey/lib/zlib/local/lib/zlibstatic.lib',
  '-DWITH_OPENSSL=ON',
  '-DOPENSSL_INCLUDE_DIR=C:/ProgramData/chocolatey/lib/openssl/local/include',
  '-DOPENSSL_ROOT_DIR=C:/ProgramData/chocolatey/lib/openssl/local',
  '-DBOOST_LIBRARYDIR=C:/ProgramData/chocolatey/lib/boost-msvc14/local/lib',
  '-DBOOST_ROOT=C:/ProgramData/chocolatey/lib/boost-msvc14/local',
  '-DWITH_STDTHREADS=ON',
  '-DWITH_MT=ON',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$sln = 'Apache Thrift.sln'
$targets = @(
  'thrift_static',
  'thriftz_static'
)
foreach ($target in $targets) {
  $msbuildArgs = @(
    `"$sln`",
    "/p:Configuration=Release",
    "/t:$target",
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs

  # Bundle debug libs for troubleshooting
  $msbuildArgs = @(
    "`"$sln`"",
    "/p:Configuration=Debug",
    "/t:$target",
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# Lastly build the Thrift Compiler
$msbuildArgs = @(
  `"$sln`",
  '/p:Configuration=Release',
  '/t:thrift-compiler',
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
$binDir = New-Item -ItemType Directory -Path 'local\bin'
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
foreach ($lib in Get-ChildItem "$buildDir\lib\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item `
    -Path $lib.Fullname `
    -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\lib\Release\*" $libDir
Copy-Item "$buildDir\bin\Release\*" $binDir
Copy-Item -Recurse "$buildDir\..\lib\cpp\src\thrift" $includeDir
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
