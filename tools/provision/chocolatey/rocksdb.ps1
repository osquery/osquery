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
$version = '5.1.4'
$chocoVersion = '5.1.4-r1'
$packageName = "rocksdb"
$projectSource = 'https://github.com/facebook/rocksdb/'
$packageSourceUrl = 'https://github.com/facebook/rocksdb/'
$authors = 'Facebook'
$owners = 'Facebook'
$copyright = 'https://github.com/facebook/rocksdb/blob/master/LICENSE'
$license = 'https://github.com/facebook/rocksdb/blob/master/LICENSE'
$url = "https://github.com/facebook/rocksdb/archive/v$version.zip"

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
Invoke-WebRequest $url -OutFile "rocksdb-$version.zip"

# Extract the source
7z x "rocksdb-$version.zip"
$sourceDir = "rocksdb-$version"
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
Add-Content -NoNewline -Path CMakeLists.txt -Value "`nset(CMAKE_CXX_FLAGS_RELEASE `"`${CMAKE_CXX_FLAGS_RELEASE} /MT`")`nset(CMAKE_CXX_FLAGS_DEBUG `"`${CMAKE_CXX_FLAGS_DEBUG} /MTd`")"

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

# Currently an issue with RocksDB's CMakeLists.txt and noisy powershell profiles,
# we backup the users profile, file, and then restore it after CMake has run.
# Generate the .sln
Move-Item -Force $PROFILE "$PROFILE.bak"
cmake -DROCKSDB_LITE=1 ..\..\ -G 'Visual Studio 14 2015 Win64'
Move-Item -Force "$PROFILE.bak" $PROFILE

# Build the libraries
msbuild rocksdb.sln /p:Configuration=Release /m /t:rocksdblib /v:m
msbuild rocksdb.sln /p:Configuration=Debug /m /t:rocksdblib /v:m

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

# Rename the Debug libraries to end with a `_dbg.lib`
foreach ($lib in Get-ChildItem "$buildDir\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\Release\*" $libDir
Copy-Item -Recurse "$buildDir\..\include\rocksdb" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
