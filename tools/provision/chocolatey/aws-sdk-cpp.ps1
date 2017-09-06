#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1.1.44'
$chocoVersion = '1.1.44'
$packageName = 'aws-sdk-cpp'
$projectSource = 'https://github.com/aws/aws-sdk-cpp'
$packageSourceUrl = "https://github.com/aws/aws-sdk-cpp/archive/$version.zip"
$authors = 'Amazon'
$owners = 'Amazon'
$copyright = 'https://github.com/aws/aws-sdk-cpp/blob/master/LICENSE'
$license = 'https://github.com/aws/aws-sdk-cpp/blob/master/LICENSE'
$url = "$packageSourceUrl"

$libs = @(
  'aws-cpp-sdk-core',
  'aws-cpp-sdk-ec2',
  'aws-cpp-sdk-sts',
  'aws-cpp-sdk-firehose',
  'aws-cpp-sdk-kinesis'
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

# Retrieve the source
Invoke-WebRequest $url -OutFile "$packageName-$version.zip"

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
$libs | Foreach-Object {
  Add-Content `
    -NoNewline `
    -Path "$_\CMakeLists.txt" `
    -Value $staticBuild
}

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path 'osquery-win-build'
Set-Location $buildDir

$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  '-G "Visual Studio 14 2015 Win64"',
  '-DSTATIC_LINKING=1',
  '-DNO_HTTP_CLIENT=1',
  '-DMINIMIZE_SIZE=ON',
  '-DBUILD_SHARED_LIBS=OFF',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$sln = 'AWSSDK.sln'
foreach($target in $libs) {
  $msbuildArgs = @(
    "`"$sln`"",
    "/p:Configuration=Release",
    "/t:$target",
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs

  # Bundle debug libs for troubleshooting
  $msbuildArgs = @(
    "`"$sln`"",
    "/p:Configuration=Debug",
    "/t:$target",
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include\aws'
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
