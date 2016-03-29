# URL of where our pre-compiled third-party dependenices are archived
$THIRD_PARTY_ARCHIVE_URL = 'https://s3.amazonaws.com/osquery-pkgs/third-party.zip'

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
  if ($packageName -eq '') {
    return $false
  }
  
  Write-Host "  Determining whether $packageName is already installed..." -foregroundcolor DarkYellow
  
  $requiresInstall = $false
  $out = choco list -lr
  
  # Parse through the locally installed chocolatey packages and look
  # to see if the supplied package already exists
  $found = $false
  $pktList = $out[1..($out.count - 1)]
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
    
    # TODO(remove me!): debug flags
    $args = @("install", "-d", "-y", "${packageName}")
    if ($packageVersion -ne '') {
      $args += @("--version", "${packageVersion}")
    }
    if ($packageOptions.count -gt 0) {
      Write-Host "       Options: $packageOptions" -foregroundcolor Cyan
      $args += ${packageOptions}
    }

    choco ${args}

  } else {
    Write-Host "    => $packageName $packageVersion already installed." -foregroundcolor Green
  }
  
  return $true
}

function Install-PipPackages {
  Write-Host "  Attempting to install Python packages" -foregroundcolor DarkYellow
  
  $env:Path = "$env:Path;$env:HOMEDRIVE\tools\python2;$env:HOMEDRIVE\tools\python2\Scripts"
  
  if ((Get-Command 'python.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "    => ERROR: failed to find python" -foregroundcolor Red
    return $false
  } else {
    Write-Host "    => Found python, continuing on..." -foregroundcolor Green
  }
  
  if ((Get-Command 'pip.exe' -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "    => ERROR: failed to find pip" -foregroundcolor Red
    return $false
  } else {
    Write-Host "    => Found pip, continuing on..." -foregroundcolor Green
  }
  
  $requirements = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'requirements.txt'))
  
  Write-Host "  Upgrading pip..." -foregroundcolor DarkYellow
  python -m pip install --upgrade pip
  
  Write-Host "  Installing from requirements.txt" -foregroundcolor DarkYellow
  pip install -r $requirements.path
  
  return $true
}

function Install-ThirdPartyPackages {
  Write-Host "  Retrieving third-party dependencies" -foregroundcolor DarkYellow
  
  $thirdPartyArchive = [System.IO.Path]::GetTempFileName()
  
  # Download our pre-compiled third-party dependencies
  Write-Host "  Downloading archive of third-party dependencies from $THIRD_PARTY_ARCHIVE_URL" -foregroundcolor DarkYellow
  (New-Object net.webclient).DownloadFile($THIRD_PARTY_ARCHIVE_URL, $thirdPartyArchive)
 
  # Extract the downloaded zip into the third-party directory in osquery root directory
  $thirdPartyRoot = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'third-party'))
  Write-Host "  Extracting archive into $thirdPartyRoot" -foregroundcolor DarkYellow
  
  # XXX: For now, we need to remove gtest-1.7.0 because it interferes with the extraction process
  $gtestPath = [System.IO.Path]::Combine($thirdPartyRoot, 'gtest-1.7.0')
  if (Test-Path -PathType Leaf $gtestPath) {
    Remove-Item $gtestPath
  }
  
  # We have the -y flag because our gtest folder needs to override the one already in third-party
  Invoke-Expression "7z x $thirdPartyArchive -y -o$thirdPartyRoot"
  
  Remove-Item $thirdPartyArchive
}

function Main {
  Write-Host "Provisioning a Win64 build environment for osquery" -foregroundcolor Yellow
  Write-Host "  Verifying script is running with Admin privileges" -foregroundcolor Yellow
  
  if (-not (Test-IsAdmin)) {
    throw "Please run this script with Admin privileges"
  }
  
  Write-Host "    => Success!" -foregroundcolor Green
  
  Install-Chocolatey

  Install-ChocoPackage '7zip.commandline'
  Install-ChocoPackage 'cmake.portable' '3.5.0'
  Install-ChocoPackage 'python2' '2.7.11'
  
  Install-PipPackages
  Install-ThirdPartyPackages
  
  $deploymentFile = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, 'vsdeploy.xml'))
  $chocoParams = @("-packageParameters", "--AdminFile ${deploymentFile}")
  Install-ChocoPackage 'visualstudio2015community' '' ${chocoParams}
  
  Write-Host "Done." -foregroundcolor Yellow
}

# TODO(remove me!): debug for now...
# $null = Main
Main