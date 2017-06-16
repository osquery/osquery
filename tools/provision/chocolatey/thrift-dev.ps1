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
$chocoVersion = '0.10.0-r2'
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
Invoke-WebRequest $url -OutFile "$packageName-$version.zip"

# Extract the source
7z x "$packageName-$version.zip"
$sourceDir = "thrift-$version"
Set-Location $sourceDir

# Thrift-dev requires this patch on windows, as our communications with the
# thrift named pipe server happen to quickly, and we get loads of verbosity
# this turns off said verbosity, as it's only concerned with our status
# pings, and not the actual result flow of extensions itself.
<#
From 9fd916be17f221660e7af28ae3bfd47d0b846a46 Mon Sep 17 00:00:00 2001
From: Nick Anderson <thor@fb.com>
Date: Tue, 30 May 2017 16:21:46 -0700
Subject: [PATCH 1/1] Patching out GLE ERROR_BROKEN_PIPE verbosity

---
 lib/cpp/src/thrift/windows/OverlappedSubmissionThread.cpp | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/lib/cpp/src/thrift/windows/OverlappedSubmissionThread.cpp b/lib/cpp/src/thrift/windows/OverlappedSubmissionThread.cpp
index 5ac6fe00..0efdfbd2 100644
--- a/lib/cpp/src/thrift/windows/OverlappedSubmissionThread.cpp
+++ b/lib/cpp/src/thrift/windows/OverlappedSubmissionThread.cpp
@@ -52,8 +52,10 @@ uint32_t TOverlappedWorkItem::overlappedResults(bool signal_failure) {
   BOOL result = ::GetOverlappedResult(h, &overlap, &bytes, TRUE);
   if (signal_failure && !result) // get overlapped error case
   {
-    GlobalOutput.perror("TPipe ::GetOverlappedResult errored GLE=", ::GetLastError());
-    throw TTransportException(TTransportException::UNKNOWN, "TPipe: GetOverlappedResult failed");
+    if(!::GetLastError() == ERROR_BROKEN_PIPE){
+      GlobalOutput.perror("TPipe ::GetOverlappedResult errored GLE=", ::GetLastError());
+      throw TTransportException(TTransportException::UNKNOWN, "TPipe: GetOverlappedResult failed");
+    }
   }
   return bytes;
 }
--
2.12.0.windows.1
#>

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

# Patches are applied in this section before build
# Windows TPipe implementations are _very_ noisy, so we squelch the output
Add-Content -NoNewline -Path "$buildDir\..\lib\cpp\CMakeLists.txt" -Value "`nadd_definitions(-DTHRIFT_SQUELCH_CONSOLE_OUTPUT=1)"

# Generate the solution files
cmake -G 'Visual Studio 14 2015 Win64' -DBUILD_COMPILER=ON -DWITH_SHARED_LIB=OFF -DBUILD_TESTING=OFF -DBUILD_TUTORIALS=OFF -DWITH_ZLIB=ON -DZLIB_INCLUDE_DIR=C:\ProgramData/chocolatey/lib/zlib/local/include -DZLIB_LIBRARY=C:/ProgramData/chocolatey/lib/zlib/local/lib/zlibstatic.lib -DWITH_OPENSSL=ON -DOPENSSL_INCLUDE_DIR=C:/ProgramData/chocolatey/lib/openssl/local/include -DOPENSSL_ROOT_DIR=C:/ProgramData/chocolatey/lib/openssl/local -DBOOST_LIBRARYDIR=C:/ProgramData/chocolatey/lib/boost-msvc14/local/lib64-msvc-14.0 -DBOOST_ROOT=C:/ProgramData/chocolatey/lib/boost-msvc14/local -DWITH_STDTHREADS=ON -DWITH_MT=ON ../

# Build the libraries
msbuild 'Apache Thrift.sln' /p:Configuration=Release /m /t:thrift_static /v:m
msbuild 'Apache Thrift.sln' /p:Configuration=Release /m /t:thriftz_static /v:m
msbuild 'Apache Thrift.sln' /p:Configuration=Debug /m /t:thrift_static /v:m
msbuild 'Apache Thrift.sln' /p:Configuration=Debug /m /t:thriftz_static /v:m
msbuild 'Apache Thrift.sln' /p:Configuration=Release /m /t:thrift-compiler /v:m

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$binDir = New-Item -ItemType Directory -Path 'local\bin'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

# Rename the Debug libraries to end with a `_dbg.lib`
foreach ($lib in Get-ChildItem "$buildDir\lib\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\lib\Release\*" $libDir
Copy-Item "$buildDir\bin\Release\*" $binDir
Copy-Item -Recurse "$buildDir\..\lib\cpp\src\thrift" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" -foregroundcolor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host "[+] Finished building $packageName v$chocoVersion." -foregroundcolor Green
}
else {
  Write-Host "[-] Failed to build $packageName v$chocoVersion." -foregroundcolor Red
}
