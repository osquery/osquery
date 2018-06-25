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
$version = '1_0_2o'
$chocoVersion = '1.0.2-o'
$packageName = 'openssl'
$projectSource = 'https://github.com/apache/thrift'
$packageSourceUrl = 'https://github.com/apache/thrift'
$authors = 'https://github.com/openssl/openssl/blob/master/AUTHORS'
$owners = 'The OpenSSL Project'
$copyright = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$license = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$url = "https://github.com/openssl/openssl/archive/OpenSSL_$version.zip"

# Public Cert bundle we bring alonge with openssl libs
$curlCerts = "https://curl.haxx.se/ca/cacert-2018-03-07.pem"
$curlCertsShaSum =
  "79ea479e9f329de7075c40154c591b51eb056d458bc4dff76d9a4b9c6c4f6d0b"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
$ret = Invoke-VcVarsAll
if ($ret -ne $true) {
	Write-Host "[-] vcvarsall.bat failed to run" Red
	exit
}

if (-not
     (
       Test-Path `
       "C:\Program Files (x86)\Windows Kits\10\Include\10.0.14393.0\ucrt"
     )
   ) {
  $msg =  "[-] NOTE: The Universal C Run Time was not found in the " +
          "system program files. Ensure that the Windows SDK is " +
          "installed."
  Write-Host $msg -ForegroundColor Yellow
}

# Check that Perl is installed
$checkPerl = Get-Command 'perl' -ErrorAction SilentlyContinue
if (-not ($checkPerl -and $checkPerl.Source.StartsWith('C:\Perl64\bin\'))) {
  $msg = "[-] This build requires perl which was not found. Please install " +
         "perl from http://www.activestate.com/activeperl/downloads and add " +
         "to the SYSTEM path before continuing"
  Write-Host $msg -ForegroundColor Red
  exit
}

# Check that NASM is installed
if (-not (Get-Command nmake -ErrorAction SilentlyContinue)) {
  $msg = "[-] This build requires NASM which was not found. Please " +
         "install from http://www.nasm.us/pub/nasm/releasebuilds/ and " +
         "add to the SYSTEM path before continuing"
  Write-Host $msg -ForegroundColor Red
  exit
}

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

# Retreive the source
$zipFile = Join-Path $(Get-Location) "$packageName-$version.zip"
if (-not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile "$zipFile"
}

$7z = (Get-Command '7z').Source
$7zargs = 'x ' + $zipFile
$perl = (Get-Command 'perl').Source
$nmake = (Get-Command 'nmake').Source

# Extract the source
Start-OsqueryProcess $7z $7zargs $false
$sourceDir = "$packageName-OpenSSL_$version"
Set-Location $sourceDir

# Build the libraries
Start-OsqueryProcess $perl 'Configure VC-WIN64A' $false
Invoke-BatchFile 'ms\do_win64a.bat'
Start-OsqueryProcess $nmake '-f ms\nt.mak' $false

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
