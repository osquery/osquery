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
$version = '5.7.1'
$chocoVersion = '5.7.1-r1'
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

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Keep track of our location to restore later
$currentLoc = Get-Location

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
$zipfile = "rocksdb-$version.zip"
if (-not (Test-Path $zipfile)) {
  Invoke-WebRequest $url -OutFile $zipfile
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "rocksdb-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x $packageName-$version.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
$staticArgs = "`nset(CMAKE_CXX_FLAGS_RELEASE " +
              "`"`${CMAKE_CXX_FLAGS_RELEASE} /MT`")" +
              "`nset(CMAKE_CXX_FLAGS_DEBUG " +
              "`"`${CMAKE_CXX_FLAGS_DEBUG} /MTd`")"
$cmakePath = Join-Path $(Get-Location) 'CMakeLists.txt'
Add-Content `
  -NoNewline `
  -Path $cmakePath `
  -Value $staticArgs

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

# Currently an issue with RocksDB's CMakeLists.txt and noisy powershell
# profiles, we backup the users profile, file, and then restore it
# after CMake has run.

# Generate the .sln
$envArch = [System.Environment]::GetEnvironmentVariable('OSQ32')
$arch = ''
$platform = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  Write-Host '[*] Building 32 bit rocksdb libs' -ForegroundColor Cyan
  $arch = 'Win32'
  $platform = 'x86'
  $cmakeBuildType = 'Visual Studio 14 2015'
} else {
  Write-Host '[*] Building 64 bit rocksdb libs' -ForegroundColor Cyan
  $arch = 'x64'
  $platform = 'amd64'
  $cmakeBuildType = 'Visual Studio 14 2015 Win64'
}

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" $platform

$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  "-G `"$cmakeBuildType`"",
  '-DPORTABLE=ON',
  '-DROCKSDB_LITE=ON',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$configurations = @(
  'Release',
  'Debug'
)
foreach($cfg in $configurations) {
  $msbuildArgs = @(
    'rocksdb.sln',
    "/p:Configuration=$cfg",
    "/p:Platform=$arch",
    "/p:PlatformType=$arch",
    '/t:rocksdb',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# If the build path exists, purge it for a clean packaging
$chocoDir = Join-Path $(Get-Location) 'osquery-choco'
if (Test-Path $chocoDir) {
  Remove-Item -Force -Recurse $chocoDir
}

# Construct the Chocolatey Package
New-Item -ItemType Directory -Path 'osquery-choco'
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

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
-ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
$package = "$(Get-Location)\$packageName.$chocoVersion.nupkg"
Write-Host `
  "[+] Finished building. Package written to $package" -ForegroundColor Green
} else {
Write-Host `
  "[-] Failed to build $packageName v$chocoVersion." `
  -ForegroundColor Red
}
Set-Location $currentLoc
