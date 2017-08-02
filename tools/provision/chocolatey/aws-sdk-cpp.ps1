#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1.0.107'
$chocoVersion = '1.0.107-r1'
$packageName = 'aws-sdk-cpp'
$projectSource = 'https://github.com/aws/aws-sdk-cpp'
$packageSourceUrl = 'https://github.com/apache/thrift'
$authors = 'Amazon'
$owners = 'Amazon'
$copyright = 'https://github.com/aws/aws-sdk-cpp/blob/master/LICENSE'
$license = 'https://github.com/aws/aws-sdk-cpp/blob/master/LICENSE'
$url = "https://github.com/aws/aws-sdk-cpp/archive/$version.zip"

$libs = @(
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-ec2',
  'aws-cpp-sdk-sts',
  'aws-cpp-sdk-firehose',
  'aws-cpp-sdk-kinesis'
)

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
$sourceDir = "$packageName-$version"
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
$libs | Foreach-Object {
  Add-Content -NoNewline -Path "$_\CMakeLists.txt" -Value "`nset(CMAKE_CXX_FLAGS_RELEASE `"`${CMAKE_CXX_FLAGS_RELEASE} /MT`")`nset(CMAKE_CXX_FLAGS_DEBUG `"`${CMAKE_CXX_FLAGS_DEBUG} /MTd`")"
}

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

cmake -G 'Visual Studio 14 2015 Win64' -DSTATIC_LINKING=1 -DNO_HTTP_CLIENT=1 -DMINIMIZE_SIZE=ON -DBUILD_SHARED_LIBS=OFF ../

# Build the libraries
$libs | Foreach-Object {
  msbuild 'aws-cpp-sdk-all.sln' /p:Configuration=Release /m /t:$_ /v:m
  msbuild 'aws-cpp-sdk-all.sln' /p:Configuration=Debug /m /t:$_ /v:m
}

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include\aws'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec $packageName $chocoVersion $authors $owners $projectSource $packageSourceUrl $copyright $license

$libs | Foreach-Object {
  Copy-Item "$buildDir\$_\Release\*" $libDir
  $libPath = $_
  Get-ChildItem "$buildDir\$_\Debug" | Foreach-Object {
    $toks = $_.Name.split('.')
    $newLibName = $toks[0..$($toks.count - 2)] -join '.'
    $suffix = $toks[$($toks.count - 1)]
    Copy-Item -Path "$buildDir\$libPath\Debug\$_" -Destination "$libDir\$newLibName`_dbg.$suffix"
  }
  Copy-Item -Recurse "$buildDir\..\$_\include\aws\*" $includeDir
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
