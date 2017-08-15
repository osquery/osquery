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
$version = '4.0.1'
$chocoVersion = '4.0.1'
$packageName = 'llvm-clang'
$projectSource = 'http://llvm.org/git/llvm.git'
$packageSourceUrl = 'http://llvm.org/git/llvm.git'
$packageDigest = '139BA95F9F88199CDC419A674F0A85DF3568367623486336843207A4982E36E9'
$authors = 'llvm'
$owners = 'llvm'
$copyright = 'Copyright (c) 2003-2017 University of Illinois at Urbana-Champaign.'
$license = "https://releases.llvm.org/$version/LICENSE.TXT"
$url = "http://releases.llvm.org/$version/LLVM-$version-win64.exe"
$parentPath = $(Split-Path -Parent $MyInvocation.MyCommand.Definition)

$workingDir = Get-Location

# Invoke our utilities file
. $(Join-Path $parentPath "osquery_utils.ps1")

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
if (-not (Test-Path "$packageName-$version.exe")) {
  Invoke-WebRequest $url -OutFile "$packageName-$version.exe"
  if ($(Get-FileHash -Algorithm sha256 "$packageName-$version.exe").Hash -ne `
        $packageDigest) {
    Write-Host '[-] Download of package failed! Check connection.' `
               -foregroundcolor Red
  }
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "llvm-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = @(
      'x',
      "-ollvm-$version\local",
      "$packageName-$version.exe"
    )
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Bundle the package into a chocolatey package
Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license
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

# Restore our working directory
Set-Location $workingDir
