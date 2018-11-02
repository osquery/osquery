#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Update-able metadata
$version = '3.8.1'
$chocoVersion = '3.8.1'
$packageName = 'libyara'
$projectSource = 'https://github.com/VirusTotal/yara'
$packageSourceUrl = "https://github.com/VirusTotal/yara/archive/v$version.zip"
$authors = 'VirusTotal'
$owners = 'VirusTotal'
$copyright = 'https://github.com/VirusTotal/yara/blob/master/COPYING'
$license = 'https://github.com/VirusTotal/yara/blob/master/COPYING'
$url = "$packageSourceUrl"


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
$zipFile = "yara-$version.zip"
if(-Not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile "$zipFile"
}

# Extract the source
$sourceDir = "yara-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x $zipFile"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
##$staticBuild = "`nset(CMAKE_CXX_FLAGS_RELEASE `"`${CMAKE_CXX_FLAGS_RELEASE} " +
##              "/MT`")`nset(CMAKE_CXX_FLAGS_DEBUG `"`${CMAKE_CXX_FLAGS_DEBUG} " +
##              "/MTd`")"

#foreach($lib in $libs) {
#  Add-Content `
#    -NoNewline `
#    -Path "$lib\CMakeLists.txt" `
#    -Value $staticBuild
#}

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

#$cmake = (Get-Command 'cmake').Source
#$cmakeArgs = @(
#  '-G "Visual Studio 14 2015 Win64"',
#  '-DSTATIC_LINKING=1',
#  '-DNO_HTTP_CLIENT=1',
#  '-DMINIMIZE_SIZE=ON',
#  '-DBUILD_SHARED_LIBS=OFF',
#  '../'
#)
#Start-OsqueryProcess $cmake $cmakeArgs

$env:INCLUDE += ";C:\ProgramData\chocolatey\lib\openssl\local\include"
$env:INCLUDE += ";C:\ProgramData\chocolatey\lib\jansson\local\include"

$env:LIB += ";C:\ProgramData\chocolatey\lib\openssl\local\lib"
$env:LIB += ";C:\ProgramData\chocolatey\lib\jansson\local\lib"
$env:LIB += ";$buildDir"

$env:UseEnv='true'

## TODO: copy ssleay32.lib to libcrypto.lib
Copy-Item "C:\ProgramData\chocolatey\lib\openssl\local\lib\ssleay32.lib" "$buildDir\libcrypto.lib"

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source

##Invoke-Expression -Command:"""$msbuild"" -p:Configuration=Release ..\windows\vs2015\libyara\libyara.vcxproj"
#$sln = 'yara.sln'
  $msbuildArgs = @(
    "..\windows\vs2015\libyara\libyara.vcxproj", 
    "/p:Configuration=StaticRelease"
  )
  Start-OsqueryProcess $msbuild $msbuildArgs $false

Write-Host "After msbuild"

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-Host "Before write-nuspec"

Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license

  Copy-Item "$buildDir\..\windows\vs2015\libyara\X64\StaticRelease\*.lib" $libDir
  Copy-Item -Recurse "$buildDir\..\libyara\include\*" $includeDir

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
