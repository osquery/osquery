#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Update-able metadata
$version = '2.11'
$chocoVersion = '2.11'
$packageName = 'jansson'
$projectSource = 'https://github.com/akheron/jansson'
$packageSourceUrl = "https://github.com/akheron/jansson/archive/v$version.zip"
$authors = 'akheron'
$owners = 'akheron'
$copyright = 'https://github.com/akheron/jansson/blob/master/LICENSE'
$license = 'https://github.com/akheron/jansson/blob/master/LICENSE'
$url = "$packageSourceUrl"

$libs = @(
  'jansson'
)

# Keep current loc to restore later
$currentLoc = Get-Location

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

# Retrieve the source only if we don't already have it
$zipFile = "$packageName-$version.zip"
if(-Not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile "$zipFile"
}

# Extract the source
$sourceDir = "$packageName-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x $packageName-$version.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
$staticBuild = "`nset(CMAKE_CXX_FLAGS_RELEASE `"`${CMAKE_CXX_FLAGS_RELEASE} " +
              "/MT`")`nset(CMAKE_CXX_FLAGS_DEBUG `"`${CMAKE_CXX_FLAGS_DEBUG} " +
              "/MTd`")"

  Add-Content `
    -NoNewline `
    -Path "CMakeLists.txt" `
    -Value $staticBuild

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  '-G "Visual Studio 14 2015 Win64"',
  '-DJANSSON_STATIC_CRT=1',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$msbuildArgs = @(
    "$buildDir\jansson.vcxproj",
    "/p:Configuration=Release",
    '/m',
    '/v:m'
  )
Start-OsqueryProcess $msbuild $msbuildArgs

$msbuildArgs = @(
    "$buildDir\jansson.vcxproj",
    "/p:Configuration=Debug",
    '/m',
    '/v:m'
  )
Start-OsqueryProcess $msbuild $msbuildArgs

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
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

  Copy-Item "$buildDir\lib\Release\*" $libDir
  Copy-Item "$buildDir\lib\Debug\*" $libDir
  Copy-Item -Recurse "$buildDir\include\*" $includeDir

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
