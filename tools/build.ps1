#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Make a best effort to dot-source our utils script
$utils = Join-Path $(Get-Location) '.\tools\provision\chocolatey\osquery_utils.ps1'
if (-not (Test-Path $utils)) {
  $msg = '[-] Did not find osquery utils. This script should be run from source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}
. $utils

# A helper function to call CMake and generate our solution file
function Invoke-OsqueryCmake {
  $vsinfo = Get-VSInfo
  $cmake = (Get-Command 'cmake').Source
  if ($vsinfo.version -eq '15' -and -not (Test-Path env:OSQUERY_BUILD_HOST)){
    $cmakeArgs = @(
      '-G "Visual Studio 15 2017 Win64"',
      '-T v141'
    )
  } else {
    $cmakeArgs = @(
      '-G "Visual Studio 14 2015 Win64"',
      '-T v140'
    )
  }
  $cmakeArgs += '../../'
  $null = Start-OsqueryProcess $cmake $cmakeArgs $false
}

# A helper function for build the osquery binaries. This must be
# run in the same directory where osquery.sln is located, and it's
# assumed that cmake has already been run.
function Invoke-OsqueryMsbuild {
  # Derive what type of release to build
  $relEnv = [environment]::GetEnvironmentVariable("RELWITHDEBINFO")
  $rel = 'Release'
  if ($relEnv -ne $null) {
    Write-Host '[+] Building RelWithDebInfo osquery' -ForegroundColor Cyan
    $rel = 'RelWithDebInfo'
  }

  # Build the binaries
  $msbuild = (Get-Command 'msbuild').Source
  $sln = 'osquery.sln'
  $targets = @(
    'shell',
    'daemon',
    'example_extension'
  )
  foreach ($target in $targets) {
    $msbuildArgs = @(
      "`"$sln`"",
      "/p:Configuration=$rel",
      "/t:$target",
      '/m',
      '/v:m'
    )
    $ret = Start-OsqueryProcess $msbuild $msbuildArgs $false
    # The build failed, bail out early
    if ($ret.exitcode -ne 0) {
      return $ret
    }
  }

  # If the build failed, or we're skipping tests return
  $skipTests = [environment]::GetEnvironmentVariable("SKIP_TESTS")
  if (($ret.exitcode -ne 0) -or ($skipTests -ne $null)) {
    return $ret
  }

  $targets = @(
    'osquery_tests',
    'osquery_additional_tests',
    'osquery_tables_tests'
  )
  foreach ($target in $targets) {
    $msbuildArgs = @(
      "`"$sln`"",
      "/p:Configuration=$rel",
      "/t:$target",
      '/m',
      '/v:m'
    )
    $ret = Start-OsqueryProcess $msbuild $msbuildArgs $false
    # The build failed, bail out early
    if ($ret.exitcode -ne 0) {
      exit $ret.exitcode
    }
  }

  # And finally, run the tests
  $ctest = (Get-Command 'ctest').Source
  $ctestArgs = @(
    '-C',
    "$rel",
    '--output-on-failure'
  )
  $ret = Start-OsqueryProcess $ctest $ctestArgs $false
  return $ret
}

# A function for running cmake to generate the osquery solution,
# building the osquery project, and lastly running our tests
function Invoke-OsqueryBuild {

  # Create our build directory if it doesn't exist
  $currentDir = Get-Location
  $buildDir = Join-Path $currentDir 'build/windows10'
  if (-not (Test-Path $buildDir)) {
    $null = New-Item -Force -ItemType Directory -Path "$buildDir"
  }
  $null = Set-Location $buildDir
  $sw = [System.Diagnostics.StopWatch]::startnew()

  # Only invoke the Visual Studio build script once to avoid polluting
  # the env. During invokation of 'make-win64-binaries' script, this
  # will always get run as the powershell launches in it's own instance
  # but we still check for those who . invoke the functions
  $vc = [environment]::GetEnvironmentVariable("VCToolsInstallDir")
  $ret = $false
  if ($vc -eq $null) {
    $ret = Invoke-VcVarsAll
  }
  if ($ret -ne $true) {
    $msg = "`n[-] Failed to find vs build tools. Re-run " + 
           'tools\make-win64-dev-env.bat'
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  Invoke-OsqueryCmake

  $ret = Invoke-OsqueryMsbuild
  if ($ret.exitcode -ne 0) {
    $msg = "`n[-] osquery build failed."
    Write-Host $msg -ForegroundColor Red
    exit $ret.exitcode
  }

  $null = Set-Location $currentDir
  Write-Host "`n[+] Build finished in $($sw.ElapsedMilliseconds) ms"
  return $ret.exitcode
}

# If the script is being invoked directly, we call our build function
$ret = Invoke-OsqueryBuild
exit $ret
