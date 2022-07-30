<#
  Copyright (c) 2014-present, The osquery authors

  This source code is licensed as defined by the LICENSE file found in the
  root directory of this source tree.

  SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#>

#
# Download and extract Strawberry Perl
#

function PrintUsage
{
  $script_name=$(Split-Path -Path $MyInvocation.ScriptName -Leaf)
  Write-Host "`nUsage:`n$script_name <download_folder>"
}

$download_folder = $args[0]
$install_folder = "C:\Strawberry"
$version = "5.32.1.1"

if([string]::IsNullOrEmpty($download_folder))
{
  Write-Error "Missing the download folder argument"
  PrintUsage
  exit 1
}

$filename = "strawberry-perl-$version-64bit.zip"
$downloaded_file = "$download_folder\$filename"

# Only download the file if it's not already there
if(-not (Test-Path -Path $downloaded_file))
{
  Write-Host "Downloading $filename..."
  (New-Object System.Net.WebClient).DownloadFile("https://strawberryperl.com/download/$version/$filename", $downloaded_file)
}

# Prefer 7zip if present, which is faster
if (Get-Command 7z -errorAction SilentlyContinue)
{
	7z x -o"$install_folder" -y "$download_folder\$filename"
}
else
{
	Write-Host "Couldn't find 7zip, will use the slower Expand-Archive"
	Expand-Archive -Path "$download_folder\$filename" -DestinationPath $install_folder -Force
}
