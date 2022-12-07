# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

param(
  [string] $startupArgs = "",
  [switch] $install = $false,
  [switch] $uninstall = $false,
  [switch] $forceuninstall = $false,
  
  [switch] $start = $false,
  [switch] $stop = $false,
  
  [switch] $help = $false,
  [switch] $debug = $false,

  [switch] $installWelManifest = $false,
  [switch] $uninstallWelManifest = $false,
  [string] $welManifestPath = (Join-Path $PSScriptRoot "osquery.man")
)

$kServiceName = "osqueryd"
$kServiceDescription = "osquery daemon service"

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

function Do-Help {
  $programName = (Get-Item $PSCommandPath ).Name
  
  Write-Host "Usage: $programName (-install|-uninstall|-forceuninstall|-start|-stop|-help)" -foregroundcolor Yellow
  Write-Host ""
  Write-Host "  Only one of the following options can be used. Using multiple will result in "
  Write-Host "  options being ignored."
  Write-Host "    -install                  Install the osqueryd service"
  Write-Host "    -startupArgs              Specifies additional arguments for the service (only used with -install)"
  Write-Host "    -uninstall                Uninstall the osqueryd service"
  Write-Host "    -forceuninstall           It uninstalls the installed osquery package"
  Write-Host "    -start                    Start the osqueryd service"
  Write-Host "    -stop                     Stop the osqueryd service"
  Write-Host "    -installWelManifest       Installs the Windows Event Log manifest"
  Write-Host "    -uninstallWelManifest     Uninstalls the Windows Event Log manifest"
  Write-Host "    -welManifestPath <path>   The Windows Event Log manifest path"
  Write-Host ""
  Write-Host "    -help                     Shows this help screen"
  
  Exit 1
}

Function Get-OsqueryBinPath {
  $serviceBinaryPath = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'osquery', 'osqueryd', 'osqueryd.exe'))
  if (-not (Test-Path $serviceBinaryPath)) {
    Write-Host "'$serviceBinaryPath' is not a valid file. Did you build the osquery daemon?" -foregroundcolor Red
    Exit -1
  }

  return $serviceBinaryPath
}

function Do-Service {

  $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"
  
  if ($install) {
    $kServiceBinaryPath = Get-OsqueryBinPath
    if ($osquerydService) {
      Write-Host "'$kServiceName' is already installed." -foregroundcolor Yellow
      Exit 1
    } else {
      New-Service -BinaryPathName "$kServiceBinaryPath $startupArgs" `
                  -Name $kServiceName `
                  -DisplayName $kServiceName `
                  -Description $kServiceDescription `
                  -StartupType Automatic
      Write-Host "Installed '$kServiceName' system service." -foregroundcolor Cyan
      Exit 0
    }
  } elseif ($uninstall) {
    if ($osquerydService) {
      Stop-Service $kServiceName
      
      Write-Host "Found '$kServiceName', stopping the system service..."
      
      Start-Sleep -s 5
      
      Write-Host "System service should be stopped."
      
      $osquerydService.Delete()
      Write-Host "System service '$kServiceName' uninstalled." -foregroundcolor Cyan
      
      Exit 0
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1
    }
  } elseif ($forceuninstall) {
    # Grabbing the location of msiexec.exe
    $targetBinPath = Resolve-Path "$env:windir\system32\msiexec.exe"
    if (!(Test-Path $targetBinPath)) {
      Write-Host "msiexec.exe cannot be located." -foregroundcolor Yellow
      Exit 1
    }

    # Creating a COM instance of the WindowsInstaller.Installer COM object
    $Installer = New-Object -ComObject WindowsInstaller.Installer
    if (!$Installer) {
      Write-Host "There was a problem retrieving the installed packages." -foregroundcolor Yellow
      Exit 1
    }

    # Enumerating the installed packages
    $ProductEnumFlag = 7 #installed packaged enumeration flag
    $InstallerProducts = $Installer.ProductsEx("", "", $ProductEnumFlag); 
    if (!$InstallerProducts) {
      Write-Host "Installed packages cannot be retrieved." -foregroundcolor Yellow
      Exit 1
    }

    # Iterating over the installed packages results and checking for osquery package
    ForEach ($Product in $InstallerProducts) {

        $ProductCode = $null
        $VersionString = $null
        $ProductPath = $null

        try {
            $ProductCode = $Product.ProductCode()
            $VersionString = $Product.InstallProperty("VersionString")
            $ProductPath = $Product.InstallProperty("ProductName")
        }
        catch { }

        if ($ProductPath -like 'osquery') {
          Write-Host "Force uninstall of $ProductPath version $VersionString."  -foregroundcolor Cyan
          $InstallProcess = Start-Process $targetBinPath -ArgumentList "/quiet /x $ProductCode" -PassThru -Verb RunAs -Wait
          if ($InstallProcess.ExitCode -eq 0) {
            Write-Host "Osquery was successfully uninstalled." -foregroundcolor Cyan
            Exit 0
          } else {
            Write-Host "There was an error uninstalling osquery. Error code was: $($InstallProcess.ExitCode)." -foregroundcolor Yellow
            Exit 1
          }
        }
    }

    Write-Host "Osquery is not installed on the system." -foregroundcolor Cyan
  } elseif ($start) {
    if ($osquerydService) {
      Start-Service $kServiceName
      Write-Host "'$kServiceName' system service is started." -foregroundcolor Cyan
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1
    }
  } elseif ($stop) {
    if ($osquerydService) {
      Stop-Service $kServiceName
      Write-Host "'$kServiceName' system service is stopped." -foregroundcolor Cyan
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1      
    }
  } elseif ($installWelManifest) {
    if (-not (Test-Path $welManifestPath)) {
      Write-Host "[-] Failed to find the osquery Event Log manifest file! ($welManifestPath)" -ForegroundColor Red
      Exit 1
    }

    wevtutil im $welManifestPath
    if ($?) {
      Write-Host "The Windows Event Log manifest has been successfully installed." -foregroundcolor Cyan
    } else {
      Write-Host "Failed to install the Windows Event Log manifest." -foregroundcolor Yellow
    }
  } elseif ($uninstallWelManifest) {
    if (-not (Test-Path $welManifestPath)) {
      Write-Host "[-] Failed to find the osquery Event Log manifest file! ($welManifestPath)" -ForegroundColor Red
      Exit 1
    }

    wevtutil um $welManifestPath
    if ($?) {
      Write-Host "The Windows Event Log manifest has been successfully uninstalled." -foregroundcolor Cyan
    } else {
      Write-Host "Failed to uninstall the Windows Event Log manifest." -foregroundcolor Yellow
    }
  } else {
    Write-Host "Invalid state: this should not exist!" -foregroundcolor Red
    Exit -1
  }
}

function Main {
  if (-not (Test-IsAdmin)) {
    Write-Host "Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }
  
  if ($help) {
    Do-Help
  } elseif ($debug) {
    $kServiceBinaryPath = Get-OsqueryBinPath
    $osquerydExists = Test-Path $kServiceBinaryPath
    
    Write-Host "Service Information" -foregroundcolor Cyan
    Write-Host "  kServiceName       = '$kServiceName'" -foregroundcolor Cyan
    Write-Host "  kServiceBinaryPath = '$kServiceBinaryPath'" -foregroundcolor Cyan
    Write-Host "             +exists = $osquerydExists" -foregroundcolor Cyan
    
    Exit 0
  } elseif (($install.ToBool() + $uninstall.ToBool() + $forceuninstall.ToBool() + $start.ToBool() + $stop.ToBool() + $installWelManifest.ToBool() + $uninstallWelManifest.ToBool()) -Eq 1) {
    # The above is a dirty method of determining if only one of the following booleans are true.
    Do-Service
  } else {
    Write-Host "Invalid option selected: please see -help for usage details." -foregroundcolor Red
    Exit -1
  }
}

$null = Main
