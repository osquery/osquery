#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Make a best effort to dot-source our utils script
$utils = Join-Path $(Get-Location) '.\tools\provision\chocolatey\osquery_utils.ps1'
if (-not (Test-Path $utils)) {
  $msg = '[-] Did not find osquery utils. This script should be run from source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}
. $utils

# A helper function to derive the latest VS install and call vcvarsall.bat
function Invoke-VcVarsAll {

  # First, derive the location of the latest VS install
  Write-Host '[+] Invoking windows vcvarsall build env script'
  $vswhere = (Get-Command 'vswhere').Source
  $vswhereArgs = @('-latest')
  $vswhereOut = (Start-OsqueryProcess $vswhere $vswhereArgs).stdout
  $vsLoc = ''
  $vsVersion = ''
  foreach ($l in $vswhereOut.split([environment]::NewLine)) {
    $toks = $l.split(":")
    if ($toks.Length -lt 2) {
      continue
    }
    if ($toks[0].trim() -like 'installationVersion') {
      $vsVersion = $toks[1].Split(".")[0]
    }
    if ($toks[0].trim() -like 'installationPath') {
      $vsLoc = [System.String]::Join(":", $toks[1..$toks.Length])
    }
  }
  $vsLoc = $vsLoc.trim()
  $vsVersion = $vsVersion.trim()

  $vcvarsall = Join-Path $vsLoc 'VC'
  if ($vsVersion -eq '15') {
    $vcvarsall = Join-Path $vcvarsall '\Auxiliary\Build\vcvarsall.bat'
  } else {
    $vcvarsall = Join-Path $vcvarsall 'vcvarsall.bat'
  }
  
  # Lastly invoke the environment provisioning script
  $null = Invoke-BatchFile "$vcvarsall" "amd64"
}


# A helper function to call CMake and generate our solution file
function Invoke-OsqueryCmake {
  $cmake = (Get-Command 'cmake').Source
  $cmakeArgs = @(
    '-G "Visual Studio 14 2015 Win64"',
    '../../'
  )
  $err = Start-OsqueryProcess $cmake $cmakeArgs $false
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
    $err = Start-OsqueryProcess $msbuild $msbuildArgs $false
  }

  # If desired, build our tests
  $skipTests = [environment]::GetEnvironmentVariable("SKIP_TESTS")
  if ($skipTests -ne $null) {
    return
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
    $err = Start-OsqueryProcess $msbuild $msbuildArgs $false
  }

  # And finally, run the tests
  $ctest = (Get-Command 'ctest').Source
  $ctestArgs = @(
    '-C',
    "$rel",
    '--output-on-failure'
  )
  $err = Start-OsqueryProcess $ctest $ctestArgs $false
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
  if ($vc -eq $null) {
    Invoke-VcVarsAll
  }

  Invoke-OsqueryCmake

  Invoke-OsqueryMsbuild

  $null = Set-Location $currentDir
  Write-Host "[+] Build finished in $($sw.ElapsedMilliseconds) ms"
}

# If the script is being invoked directly, we call our build function
Invoke-OsqueryBuild

