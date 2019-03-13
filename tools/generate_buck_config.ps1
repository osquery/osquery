#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

function New-VsToolchainBuckConfig {
  if (-not (Test-Path env:VS_INSTALL_LOCATION)) {
    $vswhere = (Get-Command 'vswhere').Source
    $vsLocation = Invoke-Expression "$vswhere -latest -legacy -property installationPath" 
    $vsLocation = $vsLocation  -Replace '\\', '/'
    $vsVersion = Invoke-Expression "$vswhere -latest -legacy -property installationVersion"
  } else {
    $vsLocation = $env:VS_INSTALL_LOCATION
    $vsVersion = $env:VS_VERSION
  }

  if (-not (Test-Path env:VC_TOOLS_VERSION)) {
    $vcToolsVersion = Invoke-Expression "cat '$vsLocation/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'"
  } else {
    $vcToolsVersion = $env:VC_TOOLS_VERSION
  }

  $osType = 'x86'
  $regPrefix = 'Microsoft'
  if ((Get-WmiObject -Class Win32_ComputerSystem).SystemType -match 'x64'-eq "True") {
     $regPrefix = 'Wow6432Node'
     $osType = 'x64'
  }

  if (-not (Test-Path env:WINDOWS_SDK_VERSION)) {
    $regEntry = "HKLM:\SOFTWARE\$regPrefix\Microsoft\Microsoft SDKs\Windows\"
    $oneSdkVersion =  (Get-ChildItem -Path $regEntry -Recurse -Name) | Sort | Select-Object -first 1
    $regEntry = "HKLM:\SOFTWARE\$regPrefix\Microsoft\Microsoft SDKs\Windows\$oneSdkVersion"
    $windsdk_ver = (Get-ItemProperty -Path $regEntry -Name 'ProductVersion').ProductVersion
    $windsdk_ver = "$windsdk_ver.0"
    $windsdk = (Get-ItemProperty -Path $regEntry -Name "InstallationFolder").InstallationFolder
  } else {
    $windsdk_ver = $env:WINDOWS_SDK_VERSION
    $windsdk = $env:WINDOWS_SDK_LOCATION
  }

  $toolchain_template = @'
[cxx]
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
  interpreter = C:/Python36/python.exe
'@

  $vsLocation = $vsLocation  -Replace '\\', '/'
  $windsdk = $windsdk -Replace '\\', '/'

  $toolchain_template = $toolchain_template -Replace 'VS_INSTALL_LOCATION', $vsLocation
  $toolchain_template = $toolchain_template -Replace 'VS_TOOLS_VERSION', $vcToolsVersion

  $toolchain_template = $toolchain_template -Replace 'OS_TYPE', $osType
  $toolchain_template = $toolchain_template -Replace 'WIN_SDK_INSTALL_LOCATION', $windsdk
  $toolchain_template = $toolchain_template -Replace 'WIN_SDK_VERSION', $windsdk_ver
  $toolchain_template = $toolchain_template -Replace '//',  '/'

  Out-File -FilePath "buckconfigs/windows-x86_64/toolchain/vsToolchainFlags.bcfg" -Encoding utf8 -InputObject $toolchain_template

  $cxx_cpp = "$vsLocation/VC/Tools/MSVC/$vcToolsVersion/bin/Host$osType/$osType/"
  $wind_shared = "$windsdk/Include/$windsdk_ver/"
  $lib_path = "$windsdk/Lib/$windsdk_ver/um/$osType"
  if (!(Test-Path $vsLocation) -Or !(Test-Path -Path $cxx_cpp) -Or !(Test-Path -Path $windsdk) -Or !(Test-Path $wind_shared) -Or !(Test-Path $lib_path)) {
    Write-Host "Some of the paths that were generate are invalid :((. Please check the file and make sure everything is ok!"
    Exit 1
  }
}

if (!(Test-Path "buckconfigs/windows-x86_64/toolchain")) {
  Write-Host "Couldn't find path buckconfigs/windows-x86_64/toolchain. Please make sure you run the script from osquery/oss/tools !"
  Exit 1
}

New-VsToolchainBuckConfig
