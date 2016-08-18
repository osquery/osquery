#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# URL of where our pre-compiled third-party dependenices are archived
$THIRD_PARTY_ARCHIVE_URL = 'https://s3.amazonaws.com/osquery-pkgs/chocolatey/static'

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

# Attempts to install chocolatey if not already
function Install-Chocolatey {
  Write-Host "  Attemping to detect presence of chocolatey..." -foregroundcolor DarkYellow
  if ((Get-Command 'choco.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "    => Did not find. Installing chocolatey..." -foregroundcolor Cyan
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    $env:Path = "$env:Path;$env:ALLUSERSPROFILE\chocolatey\bin"
  } else {
    Write-Host "    => Chocolatey is already installed." -foregroundcolor Green
  }
}

# Attempts to install a chocolatey package of a specific version if 
# not already there.
function Install-ChocoPackage {
param(
  [string] $packageName = '',
  [string] $packageVersion = '',
  [array] $packageOptions = @()
) 
  Write-Host "  Determining whether $packageName is already installed..." -foregroundcolor DarkYellow
  
  $requiresInstall = $false
  $out = choco list -lr
  
  # Parse through the locally installed chocolatey packages and look
  # to see if the supplied package already exists
  $found = $false
  $pktList = $out
  ForEach ($pkg in $pktList) {
    $name, $version = $pkg -split '\|'
    
    if ($name -eq $packageName) {
      if ($packageVersion -eq '') {
        $found = $true
      } else {
        if ($version -eq $packageVersion) {
          $found = $true
        }
      }
    }
  }
  
  if (-not $found) {
    $requiresInstall = $true
  }
  
  if ($requiresInstall) {
    Write-Host "    => Did not find. Installing $packageName $packageVersion" -foregroundcolor Cyan
    
    $args = @("install", "-y", "${packageName}")
    if ($packageVersion -ne '') {
      $args += @("--version", "${packageVersion}")
    }
    if ($packageOptions.count -gt 0) {
      Write-Host "       Options: $packageOptions" -foregroundcolor Cyan
      $args += ${packageOptions}
    }

    choco ${args}
    
    if ($LastExitCode -ne 0) {
      Write-Host "      [!] $packageName $packageVersion failed to install!" -foregroundcolor Red
      Exit -1
    }
    
    Write-Host "      [*] Done." -foregroundcolor Green
  } else {
    Write-Host "    => $packageName $packageVersion already installed." -foregroundcolor Green
  }
}

function Install-PipPackages {
  Write-Host "  Attempting to install Python packages" -foregroundcolor DarkYellow
  
  $env:Path = "$env:Path;$env:HOMEDRIVE\tools\python2;$env:HOMEDRIVE\tools\python2\Scripts"
  
  if ((Get-Command 'python.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "    => ERROR: failed to find python" -foregroundcolor Red
    Exit -1
  }
    
  Write-Host "    => Found python, continuing on..." -foregroundcolor Green
  
  if ((Get-Command 'pip.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "    => ERROR: failed to find pip" -foregroundcolor Red
    Exit -1
  }
  
  Write-Host "    => Found pip, continuing on..." -foregroundcolor Green
  
  $requirements = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'requirements.txt'))
  
  Write-Host "  Upgrading pip..." -foregroundcolor DarkYellow
  python -m pip install --upgrade pip
  
  if ($LastExitCode -ne 0) {
    Write-Host "    pip upgrade FAILED" -foregroundcolor Red
    Exit -1
  }
  
  Write-Host "  Installing from requirements.txt" -foregroundcolor DarkYellow
  pip install -r $requirements.path
  
  if ($LastExitCode -ne 0) {
    Write-Host "    FAILED to install packages from requirements" -foregroundcolor Red
    Exit -1
  }
}

function Install-ThirdPartyPackages {
  Write-Host "  Retrieving third-party dependencies" -foregroundcolor DarkYellow
  
  # XXX: The code below exists because our chocolatey packages are not currently in the chocolatey
  #      repository. For now, we will download our packages locally and install from a local source.
  #      We also include the official source since thrift-dev depends on the chocolatey thrift package.
  #     
  #      Once our chocolatey packages are added to the official repository, installing the third-party
  #      dependencies will be as easy as Install-ChocoPackage '<package-name>'.
  $packages = @(
    "boost-msvc14.1.59.0", 
    "bzip2.1.0.6",
    "doxygen.1.8.11",
    "gflags-dev.2.1.2",
    "glog.0.3.4",
    "openssl.1.0.2",
    "rocksdb.4.4",
    "snappy-msvc.1.1.1.8",
    "thrift-dev.0.9.3",
    "cpp-netlib.0.12.0",
    "linenoise-ng.1.0.0"
  )
  $tmpDir = Join-Path $env:TEMP 'osquery-packages'
  Remove-Item $tmpDir -Recurse -ErrorAction Ignore
  mkdir $tmpDir
  
  Try {
    foreach ($package in $packages) {
      $downloadUrl = "$THIRD_PARTY_ARCHIVE_URL/$package.nupkg"
      $tmpFilePath = Join-Path $tmpDir "$package.nupkg"
      $packageName = ($package -Split '\.')[0]
      
      Write-Host "  Downloading $downloadUrl" -foregroundcolor DarkCyan
      
      Try {
        (New-Object net.webclient).DownloadFile($downloadUrl, $tmpFilePath)
      } catch [Net.WebException] {
        Write-Host "    Failed to download $package. Check connection?" -foregroundcolor Red
        Exit -1
      }
      
      Write-Host "    Installing $package" -foregroundcolor Cyan
      choco install -y $packageName -source "$tmpDir;http://chocolatey.org/api/v2"
      
      if ($LastExitCode -ne 0) {
        Write-Host "      FAILED to install $package" -foregroundcolor Red
        Exit -1
      }
       
      Write-Host "      DONE" -foregroundcolor Green
    }
  }
  Finally
  {
    Remove-Item $tmpDir -Recurse
  }
}

function Update-GitSubmodule {
  if ((Get-Command 'git.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "  FAILED to find git" -foregroundcolor Red
    Exit -1
  }
  
  $thirdPartyPath = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'third-party'))
  
  Write-Host "  Updating git submodules in $thirdPartyPath ..." -foregroundcolor Yellow
  
  pushd $thirdPartyPath
  git submodule update --init
  popd
  
  Write-Host "  Submodules updated!" -foregroundcolor Yellow
}

function Main {
  Write-Host "Provisioning a Win64 build environment for osquery" -foregroundcolor Yellow
  Write-Host "  Verifying script is running with Admin privileges" -foregroundcolor Yellow
  
  if (-not (Test-IsAdmin)) {
    Write-Host "Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }
  
  Write-Host "    => Success!" -foregroundcolor Green
  
  Install-Chocolatey

  Install-ChocoPackage '7zip.commandline'
  Install-ChocoPackage 'cmake.portable' '3.5.0'
  Install-ChocoPackage 'python2' '2.7.11'
  
  Install-PipPackages
  Install-ThirdPartyPackages
  Update-GitSubmodule
  
  $deploymentFile = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, 'vsdeploy.xml'))
  $chocoParams = @("--execution-timeout", "7200", "-packageParameters", "--AdminFile ${deploymentFile}")
  Install-ChocoPackage 'visualstudio2015community' '' ${chocoParams}
  
  Write-Host "Done." -foregroundcolor Yellow
}

$null = Main
