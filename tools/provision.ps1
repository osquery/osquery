#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Turn on support for Powershell Cmdlet Bindings
[CmdletBinding(SupportsShouldProcess = $true)]

# We make heavy use of Write-Host, because colors are awesome. #dealwithit.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", `
    '', `
    Scope = "Function", `
    Target = "*")]
param()

# URL of where our pre-compiled third-party dependenices are archived
$THIRD_PARTY_ARCHIVE_URL = 'https://osquery-packages.s3.amazonaws.com/choco'

# Make a best effort to dot-source our utils script
$utils = Join-Path $(Get-Location) '.\tools\provision\chocolatey\osquery_utils.ps1'
if (-not (Test-Path $utils)) {
  $msg = '[-] Did not find osquery utils. This script should be run from source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}
. $utils


# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

function Test-RebootPending {

  $rebootPendingKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion' +
                      '\Component Based Servicing\RebootPending'
  $compBasedServ = Get-ChildItem $rebootPendingKey -ErrorAction Ignore

  $winUpdateRebootKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' +
                        '\WindowsUpdate\Auto Update\RebootRequired'
  $winUpdate = Get-Item $winUpdateRebootKey -ErrorAction Ignore

  $ccm = $false
  try {
    $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
    $status = $util.DetermineIfRebootPending()
    if (($null -ne $status) -and $status.RebootPending) {
      $ccm = $true
    }
  } catch {
    $ccm = $false
  }
  return $compBasedServ -or $winUpdate -or $ccm
}

# Checks for the existence of a supplied string in the System path. If the
# string does not exist, this function adds it. If it does exist this function
# does nothing.
function Add-ToPath {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param(
    [string] $appendPath = ''
  )
  if (-not $PSCmdlet.ShouldProcess('Add-ToPath')) {
    Exit -1
  }
  if ($appendPath[-1] -ne ';') {
    $appendPath += ';'
  }
  $oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($appendPath[0] -ne ';') -and ($oldPath[-1] -ne ';')) {
    $appendPath = ';' + $appendPath
  }
  if (-not ($oldPath -imatch [regex]::escape($appendPath))) {
    $newPath = $oldPath + ';' + $appendPath
    [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
  }
  # Append the newly added path to the sessions Path variable,
  # for immediate use.
  $env:Path += $appendPath
}

# Searchs the system path for a specified directory, and if exists, deletes
# the value from the system path.
function Remove-FromPath {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param(
    [string] $removePath = ''
  )
  if (-not $PSCmdlet.ShouldProcess('Remove-FromPath')) {
    Exit -1
  }
  if ($removePath[-1] -ne ';') {
    $removePath += ';'
  }
  if ($removePath[0] -ne ';') {
    $removePath = ';' + $removePath
  }
  $oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
  if ($oldPath -imatch [regex]::escape($removePath)) {
    $newPath = $oldPath -Replace [regex]::escape($removePath), $NULL
    [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
  }
}

# Checks if a package is already installed through chocolatey
# Returns true if:
#  * The package is installed and the user supplies no version
#  * The package is installed and the version matches the user supplied version
function Test-ChocoPackageInstalled {
  param(
    [string] $packageName = '',
    [string] $packageVersion = ''
  )
  $out = choco list -lr

  # Parse through the locally installed chocolatey packages and look
  # to see if the supplied package already exists
  ForEach ($pkg in $out) {
    $name, $version = $pkg -split '\|'
    if ($name -eq $packageName) {
      if ($packageVersion -ne "" -and $packageVersion -ne $version) {
        return $false;
      }
      return $true;
    }
  }
  return $false
}

# Helper function to check the version of python installed, as well as
# return the parent path where Python is installed.
function Test-PythonInstalled {
  $major = '*2.7*'
  $pythonInstall = (Get-Command 'python' -ErrorAction SilentlyContinue).Source
  if ($pythonInstall -eq $null) {
    $msg = '[-] Python binary not found in system path'
    Write-Host $msg -ForegroundColor Yellow
    return $false
  }
  $out = Start-OsqueryProcess $pythonInstall @('--version')
  if (($out.exitcode -ne 0) -or (-not ($out.stderr -like $major))) {
    $msg = '[-] Python major version != 2.7'
    Write-Host $msg -ForegroundColor Yellow
    return $false
  }
  # Get the specific version returned
  $version = $out.stderr.Split(" ")
  if ($version.Length -lt 2) {
    $msg = '[-] Encountered unknown version of python'
    Write-Host $msg -ForegroundColor Yellow
    return $false
  }
  $minor = $version[1].Trim().Split(".")
  if ($minor.Length -le 2) {
    $msg = '[-] Encountered unknown version of python'
    Write-Host $msg -ForegroundColor Yellow
    return $false
  }
  # The oldest Python variant we support is 2.7.12
  if ([int]$minor[2] -lt 12) {
    $msg = '[-] Python minor version < 12'
    Write-Host $msg -ForegroundColor Yellow
    return $false
  }
  # Lastly derive the parent path of the binary, as we use this to
  # get the pip path also.
  return (Get-Item $pythonInstall).Directory.Fullname
}

# Installs the Powershell Analzyer: https://github.com/PowerShell/PSScriptAnalyzer
function Install-PowershellLinter {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param()
  if (-not $PSCmdlet.ShouldProcess('PSScriptAnalyzer')) {
    Exit -1
  }

  $nugetProviderInstalled = $false
  Write-Host " => Determining whether NuGet package provider is already installed." -foregroundcolor DarkYellow
  foreach ($provider in Get-PackageProvider) {
    if ($provider.Name -eq "NuGet" -and $provider.Version -ge 2.8.5.206) {
      $nugetProviderInstalled = $true
      break
    }
  }
  if (-not $nugetProviderInstalled) {
    Write-Host " => NuGet provider either not installed or out of date. Installing..." -foregroundcolor Cyan
    Install-PackageProvider -Name NuGet -Force
    Write-Host "[+] NuGet package provider installed!" -foregroundcolor Green
  } else {
    Write-Host "[*] NuGet provider already installed." -foregroundcolor Green
  }

  $psScriptAnalyzerInstalled = $false
  Write-Host " => Determining whether PSScriptAnalyzer is already installed." -foregroundcolor DarkYellow
  foreach ($module in Get-Module -ListAvailable) {
    if ($module.Name -eq "PSScriptAnalyzer" -and $module.Version -ge 1.7.0) {
      $psScriptAnalyzerInstalled = $true
      break
    }
  }

  if (-not $psScriptAnalyzerInstalled) {
    if((Get-Command Install-Module).Source -eq 'PsGet') {
      $msg = '[-] Conflicting package manager PsGet found, skipping ' +
             'Powershell modules.'
      Write-Host $msg -ForegroundColor Yellow
    } else {
      $msg = ' => PSScriptAnalyzer either not installed or ' +
      'out of date. Installing...'
      Write-Host $msg -foregroundcolor Cyan
      Install-Module -Name PSScriptAnalyzer -Force
      Write-Host "[+] PSScriptAnalyzer installed!" -foregroundcolor Green
    }
  } else {
    Write-Host "[*] PSScriptAnalyzer already installed." -foregroundcolor Green
  }
}

# Attempts to install chocolatey if not already
function Install-Chocolatey {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", "")]
  param()
  if (-not $PSCmdlet.ShouldProcess('Chocolatey')) {
    Exit -1
  }
  Write-Host " => Attemping to detect presence of chocolatey..." -foregroundcolor DarkYellow
  if ($null -eq (Get-Command 'choco.exe' -ErrorAction SilentlyContinue)) {
    if (Test-Path "$env:ALLUSERSPROFILE\chocolatey\bin") {
      Write-Host "[-] WARN: Chocolatey appears to be installed, but cannot be found in the system path!" -foregroundcolor Yellow
    } else {
      Write-Host " => Did not find. Installing chocolatey..." -foregroundcolor Cyan
      Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    Write-Host " => Adding chocolatey to path."
    $chocoPath = $env:ALLUSERSPROFILE + '\chocolatey\bin'
    Add-ToPath $chocoPath
  } else {
    Write-Host "[*] Chocolatey is already installed." -foregroundcolor Green
  }
}

# Attempts to install a chocolatey package of a specific version if
# not already there.
function Install-ChocoPackage {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param(
    [string] $packageName = '',
    [string] $packageVersion = '',
    [array] $packageOptions = @()
  )
  if (-not $PSCmdlet.ShouldProcess($packageName)) {
    Exit -1
  }
  Write-Host " => Determining whether $packageName is already installed..." -foregroundcolor DarkYellow
  $isInstalled = Test-ChocoPackageInstalled $packageName $packageVersion
  if (-not $isInstalled) {
    Write-Host " => Did not find. Installing $packageName $packageVersion" -foregroundcolor Cyan
    $args = @("install", "-s", "https://chocolatey.org/api/v2/", "-y", "-r", "${packageName}")
    if ($packageVersion -ne '') {
      $args += @("--version", "${packageVersion}")
    }
    if ($packageOptions.count -gt 0) {
      Write-Host "Options: $packageOptions" -foregroundcolor Cyan
      $args += ${packageOptions}
    }
    choco ${args}
    # Visual studio will occasionally exit with one of the following codes,
    # indicating a system reboot is needed before continuing.
    $rebootErrorCodes = @(
      3010,
      2147781575,
      -2147185721,
      -2147205120,
      -2147023436
    )
    if ($rebootErrorCodes -Contains $LastExitCode) {
      $LastExitCode = 0
    }
    if (1638 -eq $LastExitCode) {
      $LastExitCode = 0
      Write-Host "[*] WARN: A version of $packageName already exists, skipping" -foregroundcolor Yellow
    }
    if ($LastExitCode -ne 0) {
      Write-Host "[-] ERROR: $packageName $packageVersion failed to install!" -foregroundcolor Red
      Exit -1
    }
    Write-Host "[+] Done." -foregroundcolor Green
  } else {
    Write-Host "[*] $packageName $packageVersion already installed." -foregroundcolor Green
  }
}

function Install-PipPackage {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param()
  if (-not $PSCmdlet.ShouldProcess('Pip required modules')) {
    Exit -1
  }
  Write-Host " => Attempting to install Python packages" -foregroundcolor DarkYellow
  $pythonPath = [Environment]::GetEnvironmentVariable("OSQUERY_PYTHON_PATH", "Machine")
  Add-ToPath $pythonPath
  $pipPath = "$pythonPath\Scripts"
  Add-ToPath $pipPath
  if (-not (Test-Path "$pythonPath\python.exe")) {
    Write-Host "[-] ERROR: failed to find python at $pythonPath" -foregroundcolor Red
    Exit -1
  }
  if (-not (Test-Path "$pipPath\pip.exe")) {
    Write-Host "[-] ERROR: failed to find pip in $pythonPath\Scripts!" -foregroundcolor Red
    Exit -1
  }

  $requirements = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'requirements.txt'))
  Write-Host " => Upgrading pip..." -foregroundcolor DarkYellow
  & "$pythonPath\python.exe" -m pip -q install --upgrade pip
  if ($LastExitCode -ne 0) {
    Write-Host "[-] ERROR: pip upgrade failed." -foregroundcolor Red
    Exit -1
  }
  Write-Host " => Installing from requirements.txt" -foregroundcolor DarkYellow
  & "$pipPath\pip.exe" -q install -r $requirements.path
  & "$pipPath\pip.exe" -q install thrift
  if ($LastExitCode -ne 0) {
    Write-Host "[-] ERROR: Install packages from requirements failed." -foregroundcolor Red
    Exit -1
  }
}

function Install-ThirdParty {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  param()
  if (-not $PSCmdlet.ShouldProcess('Thirdparty Chocolatey Libraries')) {
    Exit -1
  }
  Write-Host " => Retrieving third-party dependencies" -foregroundcolor DarkYellow

  # List of our third party packages, hosted in our AWS S3 bucket
  $packages = @(
    "aws-sdk-cpp.1.2.7",
    "boost-msvc14.1.66.0-r1",
    "bzip2.1.0.6",
    "doxygen.1.8.11",
    "gflags-dev.2.2.1",
    "glog.0.3.5",
    "libarchive.3.3.1-r1",
    "llvm-clang.4.0.1",
    "openssl.1.0.2-o",
    "rocksdb.5.7.1-r1",
    "thrift-dev.0.11.0",
    "zlib.1.2.8",
    "rapidjson.1.1.0"
    "zstd.1.2.0-r3"
  )
  $tmpDir = Join-Path $env:TEMP 'osquery-packages'
  Remove-Item $tmpDir -Recurse -ErrorAction Ignore
  New-Item -Force -Type directory -Path $tmpDir
  Try {
    foreach ($package in $packages) {
      $chocoForce = ""
      $executionTimeout = 7200
      $packageData = $package -split '\.'
      $packageName = $packageData[0]
      $packageVersion = [string]::Join('.', $packageData[1..$packageData.length])

      Write-Host " => Determining whether $packageName is already installed..." -foregroundcolor DarkYellow
      $isInstalled = Test-ChocoPackageInstalled $packageName $packageVersion
      if ($isInstalled) {
        Write-Host "[*] $packageName $packageVersion already installed." -foregroundcolor Green
        continue
      }

      # Chocolatey package is installed, but version is off
      $oldVersionInstalled = Test-ChocoPackageInstalled $packageName
      if ($oldVersionInstalled) {
        Write-Host " => An old version of $packageName is installed. Forcing re-installation" -foregroundcolor Cyan
        $chocoForce = "-f"
      } else {
        Write-Host " => Did not find. Installing $packageName $packageVersion" -foregroundcolor Cyan
      }
      $downloadUrl = "$THIRD_PARTY_ARCHIVE_URL/$package.nupkg"
      $tmpFilePath = Join-Path $tmpDir "$package.nupkg"
      Write-Host " => Downloading $downloadUrl" -foregroundcolor DarkCyan
      Try {
        (New-Object net.webclient).DownloadFile($downloadUrl, $tmpFilePath)
        Write-Host " => Downloaded" -foregroundcolor DarkCyan
      } catch [Net.WebException] {
        Write-Host "[-] ERROR: Downloading $package failed. Check connection?" -foregroundcolor Red
        Exit -1
      }
      choco install --pre -y -r --execution-timeout=$executionTimeout $chocoForce $packageName --version=$packageVersion --source="$tmpDir;https://chocolatey.org/api/v2"
      if ($LastExitCode -ne 0) {
        Write-Host "[-] ERROR: Install of $package failed." -foregroundcolor Red
        Exit -1
      }
      Write-Host "[+] Done" -foregroundcolor Green
    }
  } Finally {
    Remove-Item $tmpDir -Recurse
  }
}

function Update-GitSubmodule {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
  param()
  if (-not $PSCmdlet.ShouldProcess('Git Submodules')) {
    Exit -1
  }
  if ($null -eq (Get-Command 'git.exe' -ErrorAction SilentlyContinue)) {
    Write-Host "[-] ERROR: Git was not found on the system. Install git." -foregroundcolor Red
    Exit -1
  }
  $repoRoot = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..'))
  $thirdPartyPath = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'third-party'))
  Write-Host " => Updating git submodules in $thirdPartyPath ..." -foregroundcolor Yellow
  Push-Location $repoRoot
  git submodule --quiet update --init
  Pop-Location
  Write-Host "[+] Submodules updated!" -foregroundcolor Yellow
}

function Main {
  if ($PSVersionTable.PSVersion.Major -lt 3.0 ) {
    Write-Output "This installer currently requires Powershell 3.0 or greater."
    Exit -1
  }

  Write-Host "[+] Provisioning a Win64 build environment for osquery" -foregroundcolor Yellow
  Write-Host " => Verifying script is running with Admin privileges" -foregroundcolor Yellow
  if (-not (Test-IsAdmin)) {
    Write-Host "[-] ERROR: Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }

  $loc = Get-Location
  Write-Host "[+] Success -- provisioning osquery from $loc" -foregroundcolor Green
  $out = Install-Chocolatey
  $out = Install-ChocoPackage 'winflexbison'
  # Get flex and bison into our path for use
  $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
  if (Test-Path (Join-Path $chocoPath 'lib\winflexbison\tools\')) {
    if (-not (Get-Command bison.exe -ErrorAction SilentlyContinue)) {
      Copy-Item (Join-Path $chocoPath 'lib\winflexbison\tools\win_bison.exe') (Join-Path $chocoPath 'bin\bison.exe')
      Copy-Item -Recurse (Join-Path $chocoPath 'lib\winflexbison\tools\data') (Join-Path $chocoPath 'bin\data')
    }
    if (-not (Get-Command flex.exe -ErrorAction SilentlyContinue)) {
      Copy-Item (Join-Path $chocoPath 'lib\winflexbison\tools\win_flex.exe') (Join-Path $chocoPath 'bin\flex.exe')
    }
  }
  $out = Install-ChocoPackage 'cppcheck'
  $out = Install-ChocoPackage '7zip.commandline'
  $out = Install-ChocoPackage 'vswhere'
  $out = Install-ChocoPackage 'cmake.portable' '3.10.2'
  $out = Install-ChocoPackage 'windows-sdk-10.0'

  # Only install python if it's not needed
  $pythonInstall = Test-PythonInstalled
  if (-not ($pythonInstall)) {
    Install-ChocoPackage 'python2'
    # Update the system path and re-derive the python install
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $pythonInstall = Test-PythonInstalled
  }

  $out = Install-ChocoPackage 'wixtoolset' '' @('--version', '3.10.3.300701')
  # Add the WiX binary path to the system path for use
  Add-ToSystemPath 'C:\Program Files (x86)\WiX Toolset v3.10\bin'

  # Convenience variable for accessing Python
  [Environment]::SetEnvironmentVariable("OSQUERY_PYTHON_PATH", $pythonInstall, "Machine")
  $out = Install-PipPackage
  $out = Update-GitSubmodule
  if (Test-Path env:OSQUERY_BUILD_HOST) {
    $out = Install-ChocoPackage 'visualcppbuildtools'
  } else {
	$vsinfo = Get-VSInfo
	# Install visual studio 2017 if no vs installation is found
    if ($vsinfo.version -ne '15' -and $vsinfo.version -ne '14') {
      $deploymentFile = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, 'vsinstall.json'))
      $chocoParams = @("--execution-timeout", "7200", "-packageParameters", "--in ${deploymentFile}")
      $out = Install-ChocoPackage 'visualstudio2017community' '' ${chocoParams}

      if (Test-RebootPending -eq $true) {
        Write-Host "[*] Windows requires a reboot to complete installing Visual Studio." -foregroundcolor yellow
        Write-Host "[*] Please reboot your system and re-run this provisioning script." -foregroundcolor yellow
        Exit 0
      }
    } else {
      Write-Host "[*] Visual Studio installation found. Skipping install." -foregroundcolor Green
    }
    if ($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Minor -lt 1 ) {
      Write-Host "[*] Powershell version is < 5.1. Skipping Powershell Linter Installation." -foregroundcolor yellow
    } else {
      $out = Install-PowershellLinter
    }
  }
  $out = Install-ThirdParty
  Write-Host "[+] Done." -foregroundcolor Yellow
}

$startProvTime = Get-Date
$null = Main
$endProvTime = Get-Date
Write-Verbose "[+] Provisioning completed in $(($endProvTime - $startProvTime).TotalSeconds) seconds."
