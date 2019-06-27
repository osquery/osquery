#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.


<#
.SYNOPSIS
This script generates the buck config used to build osquery

.DESCRIPTION
This script generates a buck configuration file for building osquery.
On sandcastle hosts, the VS and SDK install locations are in C:\tools
so we default the configuration with these values for automation, however
on developer windows virtual machines, we expect that this script is invoked
by provision.ps1, which will already be aware of the SDK and VC install
locations.

.PARAMETER VsInstall
Location of Visual Studio on the host, defaults to 'C:\tools\toolchains\vs2017_15.5\BuildTools'

.PARAMETER VcToolsVersion
The version of Visual Studio installed you'd like to use for builds, defaults to `14.12.25827`

.PARAMETER SdkInstall
The install location of the Windows SDK you'd like to build against, defaults to 'C:\tools\toolchains\vs2017_15.5\WindowsSdk\10.0.16299.91'

.PARAMETER SdkVersion
The version of the Windows SDK you'd like to build against, defaults to '10.0.16299.0'

.PARAMETER Python3Path
The path to ones Python3 interpreter

.PARAMETER BuckConfigRoot
The root directory where you're buck configs are kept

.EXAMPLE
.\provision\windows\New-VsToolChainBuckConfig.ps1

.EXAMPLE
.\provision\windows\New-VsToolChainBuckConfig.ps1 -help

.EXAMPLE
.\provision\windows\New-VsToolChainBuckConfig.ps1 -VcInstall "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Tools\MSVC\"

.NOTES
Last Updated: 05/17/2019

.LINK
https://osquery.io

#>


#Requires -Version 3.0

# These parameters are global, as we wish to be able to invoke this script directly
param(
  [string] $VsInstall = 'C:\tools\toolchains\vs2017_15.5\BuildTools\',
  [string] $VcToolsVersion = '14.12.25827',
  [string] $SdkInstall = 'C:\tools\toolchains\vs2017_15.5\WindowsSdk\10.0.16299.91',
  [string] $SdkVersion = '10.0.16299.0',
  [string] $Python3Path = 'C:\Python36\python.exe',
  [string] $BuckConfigRoot = (Join-Path $PSScriptRoot "..\..\buckconfigs")
)

function New-VsToolchainBuckConfig {
  
  Write-Host "[+] Generating buck configs. . . " -ForegroundColor Green
  Write-Host " => Checking Visual Studio install" -ForegroundColor Cyan
  $vsLocation = ''

  # If the VS Path is an argument or environment var, get it
  if ($VsInstall -and (Test-Path $VsInstall)) {
    $vsLocation = $VsInstall
  } elseif (Test-Path env:VS_INSTALL_LOCATION) {
    $vsLocation = $env:VS_INSTALL_LOCATION
  } else {
    # Otherwise we need to attempt a derivation of it's location with vswhere
    $vswhere = (Get-Command 'vswhere').Source
    $vsVerArgs = @{
      Command = "$vswhere -latest -legacy -property installationPath"
    }
    $vsLocation = Invoke-Expression @vsVerArgs
  }

  if (-not $vsLocation) {
    $msg = '[-] Failed to find Visual Studio, check your install and pass via -VsInstall'
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  # It's a bit easier to unify our paths with forward slashes as Windows doesn't mind
  $vsLocation = $vsLocation  -Replace '\\', '/'

  # We require the specific VS version as it's a part of the path
  $vcToolsVer = ''
  if ($VcToolsVersion) {
    $vcToolsVer = $VcToolsVersion
  } elseif (Test-Path env:VC_TOOLS_VERSION) {
    $vcToolsVer = $env:VC_TOOLS_VERSION
  } else {
    $loc = Join-Path $vsLocation "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
    $vcToolsVer = Get-Content $loc
  }

  $binPath = Join-Path $vsLocation "VC\Tools\MSVC\$vcToolsVer"
  if (-not (Test-Path $binPath)) {
    $msg = "[-] Failed to find VC tools at $binPath, check Visual Studio install and pass in with -VcToolsVersion"
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  Write-Host " => Checking Win10 SDK install" -ForegroundColor Cyan

  $osType = ''
  $regPrefix = 'Microsoft'
  $arch = (Get-WmiObject -Class Win32_ComputerSystem).SystemType
  if ($arch -Match 'x64') {
    $regPrefix = 'Wow6432Node'
    $osType = 'x64'
  } else {
    $msg = 'x86 Windows systems are not supported for osquery builds'
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  $winSdkPath = ''
  if ($SdkInstall -and (Test-Path $SdkInstall) -and $SdkVersion) {
    $winSdkPath = $SdkInstall
    $winSdkVer = $SdkVersion
  } elseif ((Test-Path env:WINDOWS_SDK_INSTALL) -and (env:WINDOWS_SDK_VERSION-ne '')) {
    $winSdkPath = env:WINDOWS_SDK_INSTALL
    $winSdkVer = env:WINDOWS_SDK_VERSION
  } else {
    # If both SDK install location and version are not in env or provided, attempt to derive
    $regEntry = "HKLM:\SOFTWARE\$regPrefix\Microsoft\Microsoft SDKs\Windows\"
    $sdkRegPath =  Get-ChildItem -Path $regEntry -Recurse -Name | 
                   Sort-Object | 
                   Select-Object -first 1
    $regEntry = "HKLM:\SOFTWARE\$regPrefix\Microsoft\Microsoft SDKs\Windows\$sdkRegPath"
    $winSdkVer = (Get-ItemProperty -Path $regEntry -Name 'ProductVersion').ProductVersion
    $winSdkVer += ".0"
    $winSdkPath = (Get-ItemProperty -Path $regEntry -Name "InstallationFolder").InstallationFolder
  }

  $sdkSPath = Join-Path $winSdkPath "Include\$winSdkVer"
  if (-not (Test-Path $sdkSPath)) {
    $msg = '[-] Failed to find WinSDK, check install and pass in with -SdkInstall and -SdkVersion'
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  # If the Python3 path doesn't exist, or isn't accurate, attempt to resolve it
  $python3 = ''
  if (-not $Python3Path -or (-not (Test-Path $Python3Path))) {
    # First check to see if the python in the path is version 3+
    $pathPython = (Get-Command 'python').Source
    $ver = Invoke-Expression "$pathPython --version"
    if ('3' -Match $ver) {
      $python3 = $pathPython
    } else {
      # If both SDK install location and version are not in env or provided, attempt to derive
      $regEntry = "HKCU:\Software\Python\PythonCore\"
      $pyVer = Get-ChildItem -Path $regEntry -Recurse -Name | Sort-Object | Select-Object -first 1
      $regEntry = "HKCU:\Software\Python\PythonCore\$pyVer\InstallPath"
      $python3 = (Get-ItemProperty -Path $regEntry -Name 'ExecutablePath').ExecutablePath
    }
  }
  if (-not $python3 -or (-not (Test-Path $python3))) {
    Write-Host 'Failed to find python3, check install' -ForegroundColor Red
    exit 1
  }

  $toolchain_template = @'
[cxx#windows-x86_64]
  cpp = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/cl.exe"
  cpp_type = windows

  cc = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/cl.exe"
  cc_type = windows

  cxxpp = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/cl.exe"
  cxxpp_type = windows

  cxx = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/cl.exe"
  cxx_type = windows

  asmpp = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/ml64.exe"
  asmpp_type = windows

  asm = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/ml64.exe"
  asm_type = windows_ml64

  ld = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/link.exe"
  linker_platform = windows

  ar = "VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/bin/HostOS_TYPE/OS_TYPE/lib.exe"
  archiver_platform = windows

[cxx_toolchain]
  cppflags = \
    /I"VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/include" \
    /I"VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/atlmfc/include" \
    /I"VS_INSTALL_LOCATION/VC/Auxiliary/VS/include" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/shared" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/ucrt" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/um" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/winrt"

  cflags =

  cxxppflags = \
    /I"VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/include" \
    /I"VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/atlmfc/include" \
    /I"VS_INSTALL_LOCATION/VC/Auxiliary/VS/include" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/shared" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/ucrt" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/um" \
    /I"WIN_SDK_INSTALL_LOCATION/Include/WIN_SDK_VERSION/winrt"

  cxxflags =

  ldflags = \
    /LIBPATH:"VS_INSTALL_LOCATION/VC/Tools/MSVC/VS_TOOLS_VERSION/lib/OS_TYPE" \
    /LIBPATH:"WIN_SDK_INSTALL_LOCATION/Lib/WIN_SDK_VERSION/ucrt/OS_TYPE" \
    /LIBPATH:"WIN_SDK_INSTALL_LOCATION/Lib/WIN_SDK_VERSION/um/OS_TYPE"

[python#py3]
  interpreter = PYTHON3_PATH
'@

  Write-Host " => Generating Buck Config for Win10 builds" -ForegroundColor Cyan

  $vsLocation = $vsLocation  -Replace '\\', '/'
  $winSdkPath = $winSdkPath -Replace '\\', '/'
  $python3 = $python3 -Replace '\\', '/'

  $toolchain_template = $toolchain_template -Replace 'VS_INSTALL_LOCATION', $vsLocation
  $toolchain_template = $toolchain_template -Replace 'VS_TOOLS_VERSION', $vcToolsVer

  $toolchain_template = $toolchain_template -Replace 'OS_TYPE', $osType
  $toolchain_template = $toolchain_template -Replace 'WIN_SDK_INSTALL_LOCATION', $winSdkPath
  $toolchain_template = $toolchain_template -Replace 'WIN_SDK_VERSION', $winSdkVer

  $toolchain_template = $toolchain_template -Replace 'PYTHON3_PATH', $python3

  $toolchain_template = $toolchain_template -Replace '//',  '/'

  $cxx_cpp = "$vsLocation/VC/Tools/MSVC/$vcToolsVer/bin/Host$osType/$osType/"
  $winSdkIncludePath = "$winSdkPath/Include/$winSdkVer/"
  $winSdkLibPath = "$winSdkPath/Lib/$winSdkVer/um/$osType"

  if (-not (Test-Path $cxx_cpp)) {
    $msg = "[-] Failed to find VC bin toolchain, check VS installation."
    Write-Host $msg -ForegroundColor Red
    exit 1
  }
  if (-not (Test-Path $winSdkIncludePath)) {
    $msg = "[-] Failed to find Win10 SDK Includes directory, check provisioning output."
    Write-Host $msg -ForegroundColor Red
    exit 1
  }
  if (-not (Test-Path $winSdkLibPath)) {
    $msg = "[-] Failed to find Win10 SDK Lib directory, check provisioning output."
    Write-Host $msg -ForegroundColor Red
    exit 1
  }

  # Only write out the file if all paths were able to be derived
  $bcfg = Join-Path $BuckConfigRoot "windows-x86_64/toolchain/vs2017_15.5.bcfg"
  $outArgs = @{
    FilePath = $bcfg
    Encoding = "utf8"
    InputObject = $toolchain_template
  }
  Out-File @outArgs
  Write-Host "Buck config written to $bcfg" -ForegroundColor Green
}

$null = New-VsToolchainBuckConfig
