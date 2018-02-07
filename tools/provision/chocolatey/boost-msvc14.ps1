#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# For more information -
# https://studiofreya.com/2016/09/29/how-to-build-boost-1-62-with-visual-studio-2015/
# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package
$version = '1.66.0'
$chocoVersion = '1.66.0'
$versionUnderscores = $version -replace '\.', '_'
$packageName = 'boost-msvc14'
$projectSource = `
      "http://www.boost.org/users/history/version_$versionUnderscores.html"
$packageSourceUrl = `
      "http://www.boost.org/users/history/version_$versionUnderscores.html"
$authors = 'boost-msvc14'
$owners = 'boost-msvc14'
$copyright = 'http://www.boost.org/users/license.html'
$license = 'http://www.boost.org/users/license.html'
$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
$url = "http://downloads.sourceforge.net/project/boost/boost/" +
       "$version/boost_$versionUnderscores.7z?r=&ts=$timestamp" +
       "&use_mirror=pilotfiber"
$numJobs = 2

$currentLoc = Get-Location

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScriptSource = $MyInvocation.MyCommand.Definition

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

# Retreive the source only if it doesn't already exist
if (-not (Test-Path "boost-$version.7z")) {
  Invoke-WebRequest `
    -OutFile "boost-$version.7z" `
    -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome `
    $url
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "boost_$versionUnderscores"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x boost-$version.7z"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Build the b2 binary
if ($(Get-Command 'vswhere' -ErrorAction SilentlyContinue) -eq $null) {
  Write-Host '[-] Did not find vswhere in PATH.' -foregroundcolor red
  exit
}
$b2 = Join-Path $(Get-Location) 'b2.exe'
if (-not (Test-Path $b2)) {
  Write-Debug '[*] Boost build engine not found, building'
  Invoke-BatchFile './bootstrap.bat'
}

$installPrefix = 'stage'
$arch = '64'
$toolset = 'msvc-14.0'
# Build the boost libraries
$b2x64args = @(
  "-j$numJobs",
  "--prefix=$installPrefix",
  "toolset=$toolset",
  "address-model=$arch",
  'link=static',
  'threading=multi',
  'runtime-link=static',
  'optimization=space',
  'define=BOOST_USE_WINAPI_VERSION=0x0601',
  '--with-filesystem',
  '--with-regex',
  '--with-system',
  '--with-thread',
  '--with-coroutine',
  '--with-context',
  '--layout=tagged',
  '--ignore-site-config',
  '--disable-icu'
)
Start-OsqueryProcess $b2 $b2x64args $false

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

Copy-Item "..\$installPrefix\lib\*" $libDir
Copy-Item -Recurse "..\boost" $includeDir
Copy-Item $buildScriptSource $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  $package = "$(Get-Location)\$packageName.$chocoVersion.nupkg"
  Write-Host `
    "[+] Finished building. Package written to $package" -ForegroundColor Green
}
else {
  Write-Host `
    "[-] Failed to build $packageName v$chocoVersion." `
    -ForegroundColor Red
}
Set-Location $currentLoc
