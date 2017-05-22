#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1_0_2k'
$chocoVersion = '1.0.2-k'
$packageName = 'openssl'
$projectSource = 'https://github.com/apache/thrift'
$packageSourceUrl = 'https://github.com/apache/thrift'
$authors = 'https://github.com/openssl/openssl/blob/master/AUTHORS'
$owners = 'The OpenSSL Project'
$copyright = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$license = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$url = "https://github.com/openssl/openssl/archive/OpenSSL_$version.zip"

# Public Cert bundle we bring alonge with openssl libs
$curlCerts = "https://curl.haxx.se/ca/cacert-2016-11-02.pem"
$curlCertsShaSum = "cc7c9e2d259e20b72634371b146faec98df150d18dd9da9ad6ef0b2deac2a9d3"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

if (-not (Test-Path "C:\Program Files (x86)\Windows Kits\10\Include\10.0.14393.0\ucrt")) {
  Write-Host "[-] NOTE: The Universal C Run Time was not found in the system program files. Ensure that the Windows SDK is installed." -foregroundcolor Yellow
}

# Check that Perl is installed
if (-not (Get-Command 'perl' -ErrorAction SilentlyContinue)) {
  Write-Host "[-] This build requires perl which was not found. Please install perl from http://www.activestate.com/activeperl/downloads and add to the SYSTEM path before continuing" -foregroundcolor Red
  exit
}

# Check that NASM is installed
if (-not (Get-Command nmake -ErrorAction SilentlyContinue)) {
  Write-Host "[-] This build requires NASM which was not found. Please install from http://www.nasm.us/pub/nasm/releasebuilds/ and add to the SYSTEM path before continuing" -foregroundcolor Red
  exit
}

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
Invoke-WebRequest $url -OutFile "$packageName-$version.zip"

# Extract the source
7z x "$packageName-$version.zip"
$sourceDir = "$packageName-OpenSSL_$version"
Set-Location $sourceDir

# Build the libraries
perl Configure VC-WIN64A
ms\do_win64a
nmake -f ms\nt.mak

#$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
#Set-Location $buildDir

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'
$certsDir = New-Item -ItemType Directory -Path 'local\certs'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

# Copy the libs and headers to their correct location
Copy-Item "..\out32\ssleay32.lib" $libDir
Copy-Item "..\out32\libeay32.lib" $libDir
Copy-Item -Recurse "..\inc32\openssl" $includeDir

# Grab the OpenSSL Curl cert bundle
Invoke-WebRequest $curlCerts -Outfile "$certsDir\certs.pem"
if (-not ((Get-FileHash -Algorithm sha256 "$certsDir\certs.pem").Hash -eq $curlCertsShaSum)) {
  Write-Host "[-] Warning: certs.pem sha sum mismatch!" -foregroundcolor Yellow
}

Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
