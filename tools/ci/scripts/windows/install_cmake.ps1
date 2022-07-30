<#
  Copyright (c) 2014-present, The osquery authors

  This source code is licensed as defined by the LICENSE file found in the
  root directory of this source tree.

  SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#>

function PrintUsage
{
  $script_name=$(Split-Path -Path $MyInvocation.ScriptName -Leaf)
  Write-Host "`nUsage:`n$script_name <download_folder> <install_folder> <version>"
}

$download_folder = $args[0]
$install_folder = $args[1]
$long_cmake_ver = $args[2]

if([string]::IsNullOrEmpty($download_folder))
{
  Write-Error "Missing the download folder argument"
  PrintUsage
  exit 1
}

if([string]::IsNullOrEmpty($install_folder))
{
  Write-Error "Missing the install folder argument"
  PrintUsage
  exit 1
}

if([string]::IsNullOrEmpty($long_cmake_ver))
{
  Write-Error "Missing the version folder argument"
  PrintUsage
  exit 1
}

$short_cmake_ver = $($long_cmake_ver.split(".")[0] + "." + $long_cmake_ver.split(".")[1])

$archive_name = "cmake-$long_cmake_ver-windows-x86_64.zip"
$archive_path = "$download_folder\cmake-$long_cmake_ver-windows-x86_64.zip"

$url = $("https://cmake.org/files/v" + $short_cmake_ver + "/" + $archive_name)

# Only download the file if it's not already there
if(-not (Test-Path -Path $archive_path))
{
    Write-Host "Downloading $archive_name..."
    (New-Object System.Net.WebClient).DownloadFile($url, $archive_path)
}

7z x -o"$install_folder" -y "$archive_path"
