#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# We make heavy use of Write-Host, because colors are awesome. #dealwithit.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", '', Scope = "Function", Target = "*")]
param(
  [string] $type = 'chocolatey',
  [string] $configfile = '',
  [string] $flagfile = '',
  [array] $extras = @(),
  [bool] $help = $false
)

# Import the osquery utility functions
$utils = Join-Path $(Get-Location) 'tools\provision\chocolatey\osquery_utils.ps1'
if (-not (Test-Path $utils)) {
  $msg = '[-] This script must be run from osquery source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}
. $utils

function New-MsiPackage() {
  param(
    [string] $configPath = '',
    [string] $packsPath = $(Join-Path $(Get-Location) 'packs'),
    [string] $certsPath = '',
    [string] $flagsPath = '',
    [string] $shell = 'build\windows10\osquery\Release\osqueryi.exe',
    [string] $daemon = 'build\windows10\osquery\Release\osqueryd.exe',
    [string] $version = '0.0.0',
    [array] $extras = @()
  )
  $workingDir = Get-Location
  if ((-not (Get-Command 'candle.exe')) -or 
      (-not (Get-Command 'light.exe'))) {
    $msg = '[-] WiX not found, run .\tools\make-win64-dev-env.bat.'
    Write-Host $msg -ForegroundColor Red
    exit
  }

  if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host '[-] Powershell 5.0 or great is required for this script.' `
      -ForegroundColor Red
    exit
  }

  if (-not (Test-Path (Join-Path (Get-location).Path 'tools\make-win64-binaries.bat'))) {
    Write-Host '[-] This script must be run from the osquery repo root.' `
      -ForegroundColor Red
    exit
  }

  # bundle default certs
  if (-not (Test-Path $certsPath)) {
    $msg = '[*] Did not find openssl certs.pem, skipping.'
    Write-Host $msg -ForegroundColor Yellow
  }

  # bundle default configuration
  if (-not (Test-Path $configPath)) {
    $msg = '[*] Did not find example configuration, skipping.'
    Write-Host $msg -ForegroundColor Yellow
  }

  # bundle default packs
  if (-not (Test-Path $packsPath)) {
    $msg = '[*] Did not find example packs, skipping.'
    Write-Host $msg -ForegroundColor Yellow
  }

  # Working directory and output of files will be in `build/msi`
  $buildPath = Join-Path $(Get-OsqueryBuildPath) 'msi'
  if (-not (Test-Path $buildPath)) {
    New-Item -Force -ItemType Directory -Path $buildPath
  }
  Set-Location $buildPath

  # if no flags file specified, create a stub to run the service
  if ($flagsPath -eq '') {
    $flagspath = Join-Path $buildPath 'osquery.flags'
    Write-Output '' | Out-File $flagspath -NoNewline
  }

  # We take advantage of a trick with WiX to copy folders
  Copy-Item -Recurse -Force $certsPath $(Join-Path $(Get-Location) 'certs')
  Copy-Item -Recurse -Force $packsPath $(Join-Path $(Get-Location) 'packs')
  $iconPath = Join-Path $scriptPath 'tools\osquery.ico'
  Copy-Item -Force $iconPath "$buildPath\osquery.ico"

  $wix =
  @'
<?xml version='1.0' encoding='windows-1252'?>

<?define OsqueryVersion = 'OSQUERY_VERSION'?>
<?define OsqueryUpgradeCode = 'ea6c7327-461e-4033-847c-acdf2b85dede'?>

<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi" xmlns:util="http://schemas.microsoft.com/wix/UtilExtension">
  <Product
    Name='osquery'
    Manufacturer='Facebook'
'@
$wix += "`nId='$(New-Guid)'`n"
$wix += 
@'
    UpgradeCode='$(var.OsqueryUpgradeCode)'
    Language='1033'
    Codepage='1252'
    Version='$(var.OsqueryVersion)'>

    <Package Id='*'
      Keywords='Installer'
      Description='osquery standalone installer'
      Comments='Facebooks opensource host intrusion detection agent'
      Manufacturer='Facebook'
      InstallerVersion='100'
      Languages='1033'
      Compressed='yes'
      SummaryCodepage='1252' />

    <MediaTemplate EmbedCab="yes" />

    <MajorUpgrade
      AllowSameVersionUpgrades="yes"
      DowngradeErrorMessage="A later version of osquery is already installed. Setup will now exit." />

    <Condition Message='A newer version of osquery is already installed.'>
      NOT NEWERVERSIONDETECTED
    </Condition>

    <Condition Message="You need to be an administrator to install this product.">
        Privileged
    </Condition>

    <Property Id='SOURCEDIRECTORY' Value='packs'/>

    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='CommonAppDataFolder'>
        <Directory Id='INSTALLFOLDER' Name='osquery'>
          <Directory Id='DaemonFolder' Name='osqueryd'>
            <Component Id='osqueryd'
                Guid='41c9910d-bded-45dc-8f82-3cd00a24fa2f'>
                <CreateFolder>
                <Permission User="Users" Read="yes" 
                  ReadExtendedAttributes="yes" Traverse="yes" 
                  ReadAttributes="yes" ReadPermission="yes" Synchronize="yes"
                  GenericWrite="no" WriteAttributes="no"/>
                <Permission User="Administrators" GenericAll="yes"/>
                <Permission User="SYSTEM" GenericAll="yes"/>
              </CreateFolder>
              <File Id='osqueryd'
                Name='osqueryd.exe'
                Source='OSQUERY_DAEMON_PATH'
                KeyPath='yes'/>
              <ServiceInstall Id='osqueryd'
                Name='osqueryd'
                Account='NT AUTHORITY\SYSTEM'
                Arguments='--flagfile=C:\ProgramData\osquery\osquery.flags'
                Start='auto'
                Type='ownProcess'
                Vital='yes'
                ErrorControl='critical'/>
              <ServiceControl Id='osqueryd'
                Name='osqueryd'
                Stop='both'
                Start='install'
                Remove='uninstall'
                Wait='no'/>
            </Component>
          </Directory>
          <Component Id='osqueryi' Guid='6a49524e-52b0-4e99-876f-ec50c0082a04'>
            <File Id='osqueryi'
              Name='osqueryi.exe'
              Source='OSQUERY_SHELL_PATH'
              KeyPath='yes'/>
          </Component>
          <Component Id='extras' Guid='3f435561-8fe7-4725-975a-95930c44d063'>
            <File Id='osquery.conf'
              Name='osquery.conf'
              Source='OSQUERY_CONF_PATH'
              KeyPath='yes'/>
            <File Id='osquery.flags'
              Name='osquery.flags'
              Source='OSQUERY_FLAGS_PATH'/>
            <File Id='osquery_utils.ps1'
              Name='osquery_utils.ps1'
              Source='OSQUERY_UTILS_PATH'/>
            <File Id='manage_osqueryd.ps1'
              Name='manage-osqueryd.ps1'
              Source='OSQUERY_MGMT_PATH'/>
'@
# Bundle along any addition files specified
$cnt = 0
foreach ($e in $extras) {
  $name = Split-Path $e -Leaf
  $wix += "`n<File Id='extra_$cnt' Name='$name' Source='$e'/>`n"
  $cnt += 1
}
$wix += @'
            </Component>
            <Directory Id='PacksFolder' Name='packs'>
              <Component Id='packs'
                  Guid='e871e2b6-953e-4930-888b-78426816e566'>
              <CreateFolder/>

'@
# All files must be explicitly listed for WiX
$cnt = 0
foreach ($p in $(Get-ChildItem $packsPath)) {
  $wix += "<File Id='pack_$cnt.conf' Name='$p' Source='$packsPath\$p'/>`n"
  $cnt += 1
}
$wix += 
@'
               </Component>
             </Directory>
             <Directory Id='CertsFolder' Name='certs'>
             <Component Id='certs'
                 Guid='bb27566a-6c31-4024-8f72-28709f919b08'>
             <CreateFolder/>
'@
$cnt = 0
foreach ($c in $(Get-ChildItem $certsPath)) {
  $wix += "`n<File Id='cert_$cnt' Name='$c' Source='$certsPath\$c'/>`n"
  $cnt += 1
}

$wix += @'
            </Component>
          </Directory>
          <Directory Id="FileSystemLogging" Name="log"/>
        </Directory>
      </Directory>
    </Directory>

    <Icon Id="osquery.ico" SourceFile="OSQUERY_IMAGE_PATH"/>
    <Property Id="ARPPRODUCTICON" Value="osquery.ico" />

    <Component Id='logs'
                Directory='FileSystemLogging'
                Guid='bda18e0c-d356-441d-a264-d3e2c1718979'>
      <CreateFolder/>
    </Component>

    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='osqueryd'/>
      <ComponentRef Id='osqueryi'/>
      <ComponentRef Id='packs'/>
      <ComponentRef Id='certs'/>
      <ComponentRef Id='logs'/>
      <ComponentRef Id='extras'/>
    </Feature>
  </Product>
</Wix>
'@

  # Replace all of the WiX variables
  $wix = $wix -Replace 'OSQUERY_VERSION', "$version"
  $wix = $wix -Replace 'OSQUERY_PACKS_PATH', "packs"
  $wix = $wix -Replace 'OSQUERY_FLAGS_PATH', "$flagsPath"
  $wix = $wix -Replace 'OSQUERY_CONF_PATH', "$configPath"
  $wix = $wix -Replace 'OSQUERY_SHELL_PATH', "$shell"
  $wix = $wix -Replace 'OSQUERY_DAEMON_PATH', "$daemon"
  $wix = $wix -Replace 'OSQUERY_UTILS_PATH', "$utils"
  $wix = $wix -Replace 'OSQUERY_CERTS_PATH', "certs"
  $wix = $wix -Replace 'OSQUERY_IMAGE_PATH', "$buildPath\osquery.ico"
  $wix = $wix -Replace 'OSQUERY_MGMT_PATH', "$scriptPath\tools\manage-osqueryd.ps1"
  
  $wix | Out-File -Encoding 'UTF8' "$buildPath\osquery.wxs"

  $candle = (Get-Command 'candle').Source
  $candleArgs = @(
    "$buildPath\osquery.wxs"
  )
  Start-OsqueryProcess $candle $candleArgs

  $msi = Join-Path $buildPath "osquery.$version.msi"
  $light = (Get-Command 'light').Source
  $lightArgs = @(
    "$buildPath\osquery.wixobj",
    "-o $msi"
  )
  Start-OsqueryProcess $light $lightArgs

  if (-not (Test-Path $msi)) {
    $msg = "[-] MSI Creation failed."
    Write-Host $msg -ForegroundColor Red
  } else {
    $msg = "[+] MSI Package written to $msi"
    Write-Host $msg -ForegroundColor Green
  }

  Set-Location $workingDir
}

function New-ChocolateyPackage() {
  param(
    [string] $shell = 'build\windows10\osquery\Release\osqueryi.exe',
    [string] $daemon = 'build\windows10\osquery\Release\osqueryd.exe',
    [string] $version = '0.0.0',
    [string] $latest = '0.0.0'
  )
  $working_dir = Get-Location
  if (-not (Get-Command '7z.exe')) {
    $msg = '[-] 7z note found, run .\tools\make-win64-dev-env.bat.'
    Write-Host $msg -ForegroundColor Red
    exit
  }

  if ($PSVersionTable.PSVersion.Major -lt 5) {
    $msg = '[-] Powershell 5.0 or great is required for this script.'
    Write-Host $msg -ForegroundColor Red
    exit
  }

  # Listing of artifacts bundled with osquery
  $scriptPath = Get-Location
  $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
  $certs = Join-Path "$chocoPath" 'lib\openssl\local\certs'
  if (-not (Test-Path $certs)) {
    $msg = '[*] Did not find openssl certs.pem'
    Write-Host $msg -ForegroundColor Yellow
  }

  $conf = Join-Path $scriptPath 'tools\deployment\osquery.example.conf'
  if (-not (Test-Path $conf)) {
    $msg = '[*] Did not find example configuration'
    Write-Host $msg -ForegroundColor Yellow
  }

  $packs = Join-Path $scriptPath 'packs'
  if (-not (Test-Path $packs)) {
    Write-Host "[*] Did not find example packs" -ForegroundColor Yellow
  }

  $lic = Join-Path $scriptPath 'LICENSE'
  if (-not (Test-Path $lic)) {
    $msg = '[*] Did not find LICENSE file, package will fail ' +
           'chocolatey validation'
    Write-Host $msg -ForegroundColor Yellow
  }

  $buildDir = "$scriptPath\build\windows10\osquery\Release\"
  $clientPath = Join-Path $buildDir 'osqueryi.exe'
  $daemonPath = Join-Path $buildDir 'osqueryd.exe'
  $windowsEventLogManifestPath = Join-Path (Get-location).Path "tools\wel\osquery.man"
  $mgmtScript = "$scriptPath\tools\manage-osqueryd.ps1"

  $nupkg =
  @'
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>osquery</id>
    <version>OSQUERY_VERSION</version>
    <title>osquery</title>
    <authors>Facebook</authors>
    <owners>Facebook</owners>
    <copyright>Copyright (c) 2014-present, Facebook, Inc. All rights reserved.</copyright>
    <projectUrl>https://osquery.io</projectUrl>
    <iconUrl>https://osquery.io/static/site/img/logo-big.png</iconUrl>
    <licenseUrl>https://github.com/facebook/osquery/blob/master/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <projectSourceUrl>https://github.com/facebook/osquery</projectSourceUrl>
    <docsUrl>https://osquery.readthedocs.io/en/stable</docsUrl>
    <mailingListUrl>https://osquery-slack.herokuapp.com/</mailingListUrl>
    <bugTrackerUrl>https://github.com/facebook/osquery/issues</bugTrackerUrl>
    <tags>InfoSec Tools</tags>
    <summary>
      osquery gives you the ability to query and log things like running
      processes, logged in users, password changes, usb devices, firewall
      exceptions, listening ports, and more.
    </summary>
    <description>
      osquery allows you to easily ask questions about your Linux, OSX, and
      Windows infrastructure. Whether your goal is intrusion detection,
      infrastructure reliability, or compliance, osquery gives you the ability
      to empower and inform a broad set of organizations within your company.

      ### Package Parameters
      * `/InstallService` - This creates a new windows service that will auto-start the daemon.

      These parameters can be passed to the installer with the user of `-params`.
      For example: `-params '"/InstallService"'`.
    </description>
    <releaseNotes>
'@
  $nupkg += "https://github.com/facebook/osquery/releases/tag/$latest"
  $nupkg +=
  @'
</releaseNotes>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
'@
  $nupkg = $nupkg -Replace 'OSQUERY_VERSION', $version
  $chocoBuildPath = "$scriptPath\build\chocolatey"
  $osqueryChocoPath = "$chocoBuildPath\osquery"
  New-Item -Force -ItemType Directory -Path "$osqueryChocoPath\tools\bin"
  Copy-Item -Recurse -Force "$scriptPath\tools\deployment\chocolatey\tools" "$osqueryChocoPath"
  Copy-Item -Recurse -Force "$scriptPath\tools\provision\chocolatey\osquery_utils.ps1" "$osqueryChocoPath\tools\osquery_utils.ps1"

  $binDir = "$scriptPath\build\windows10\osquery\Release\"
  $clientPath = Join-Path $binDir 'osqueryi.exe'
  $daemonPath = Join-Path $binDir 'osqueryd.exe'
  $mgmtScript = "$scriptPath\tools\manage-osqueryd.ps1"
  $license = Join-Path "$osqueryChocoPath\tools\" 'LICENSE.txt'
  Copy-Item $lic $license
  $verification = Join-Path "$osqueryChocoPath\tools\" 'VERIFICATION.txt'
  $verMessage =
  @'
To verify the osquery binaries are valid and not corrupted, one can run one of the following:

C:\Users\> Get-FileHash -Algorithm SHA256 .\build\windows10\osquery\Release\osqueryd.exe
C:\Users\> Get-FileHash -Algorithm SHA1 .\build\windows10\osquery\Release\osqueryd.exe
C:\Users\> Get-FileHash -Algorithm MD5 .\build\windows10\osquery\Release\osqueryd.exe

And verify that the digests match one of the below values:

'@
  $verMessage += 'SHA256: ' + (Get-FileHash -Algorithm SHA256 $daemonPath).Hash + "`r`n"
  $verMessage += 'SHA1: ' + (Get-FileHash -Algorithm SHA1 $daemonPath).Hash + "`r`n"
  $verMessage += 'MD5: ' + (Get-FileHash -Algorithm MD5 $daemonPath).Hash + "`r`n"

  $verMessage | Out-File -Encoding "UTF8" $verification
  $nupkg | Out-File -Encoding "UTF8" "$osqueryChocoPath\osquery.nuspec"
  if (-not ((Test-Path $clientPath) -or (Test-Path $daemonPath))) {
    Write-Host '[-] Unable to find osquery binaries!  Check the results of the build scripts!' -ForegroundColor Red
    exit
  }

  $7z = (Get-Command '7z.exe').Source
  # This bundles up all of the files we distribute.
  $7zArgs = @(
    'a',
    "$osqueryChocoPath\tools\bin\osquery.zip",
    "$clientPath",
    "$daemonPath",
    "$certs",
    "$conf",
    "$packs",
    "$mgmtScript",
    "$license",
    "$verification",
    "$windowsEventLogManifestPath"
  )
  Start-OsqueryProcess $7z $7zArgs
  Set-Location "$osqueryChocoPath"
  choco pack

  $packagePath = Join-Path $osqueryChocoPath "osquery.$version.nupkg"
  Write-Host "[+] Chocolatey Package written to $packagePath" `
    -ForegroundColor Green
  Set-Location $working_dir
}

function Get-Help {
  $programName = (Get-Item $PSCommandPath ).Name
  $msg =  "Usage: $programName [-type] [-extras] `n" + 
          "    -help       Prints this message`n" +
          "    -type       The type of package to build, can be 'chocolatey' or 'msi'`n" +
          "    -extras     Any additional files to bundle with the packages (msi only)`n`n"
  Write-Host $msg -ForegroundColor Yellow
  exit
}

function Main() {

  if ($help) {
    Get-Help
  }

  $scriptPath = Get-Location
  $buildPath = Join-Path $scriptPath 'build\windows10\osquery\Release'
  $daemon = Join-Path $buildPath 'osqueryd.exe'
  $shell = Join-Path $buildPath 'osqueryi.exe'

  if ((-not (Test-Path $shell)) -or (-not (Test-Path $daemon))) {
    $msg = '[-] Did not find Release binaries, check build script output.'
    Write-Host $msg -ForegroundColor Red
    exit
  }

  $git = Get-Command 'git'
  $gitArgs = @(
    'describe',
    '--tags'
  )
  $version = $(Start-OsqueryProcess $git $gitArgs).stdout
  $latest = $version.split('-')[0]
  # If split len is greater than 1, this is a pre-release. Chocolatey is 
  # particular about the format of the version for pre-releases.
  if ($version.split('-').length -eq 3) {
    $version = $latest + '-' + $version.split('-')[2]
  }

  if ($type.ToLower() -eq 'msi') {
    Write-Host '[*] Building osquery MSI' -ForegroundColor Cyan
    $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
    $certs = $(Join-Path $chocoPath 'lib\openssl\local\certs')
    if ($configfile -eq '') {
      $configfile = $(Join-Path (Get-Location) 'tools\deployment\osquery.example.conf')
    }
    New-MsiPackage -shell $shell `
                   -daemon $daemon `
                   -certsPath $certs `
                   -flagsPath $flagfile `
                   -configPath $configfile `
                   -version $latest `
                   -extras $extras
  } else {
    Write-Host '[*] Building osquery Chocolatey package' -ForegroundColor Cyan
    New-ChocolateyPackage -shell $shell `
                          -daemon $daemon `
                          -version $version `
                          -latest $latest
  }
}

$null = Main
