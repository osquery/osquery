# We make heavy use of Write-Host, because colors are awesome. #dealwithit.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", '', Scope="Function", Target="*")]
param()

function Main() {
  if (-not (Get-Command 7z.exe)) {
    Write-Host '[-] 7z note found!  Please run .\tools\make-win64-dev-env.bat before continuing!' -ForegroundColor Red
    exit
  }

  if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host '[-] Powershell 5.0 or great is required for this script.' -ForegroundColor Red
    exit
  }

  $version = git describe --tags
  $latestFullVersion = (git tag)[-2]
  # If split len is greater than 1, this is a pre-release. Chocolatey is particular
  # about the format of the version for pre-releases.
  if ($version.split('-').length -eq 3) {
    $version = $version.split('-')[0] + '-' + $version.split('-')[2]
  }

  if (-not (Test-Path (Join-Path (Get-location).Path 'tools\make-win64-binaries.bat'))) {
    Write-Host "[-] Did not find build script '.\tools\make-win64-binaries.bat'!" -ForegroundColor Red
    Write-Host "[-] This script must be run from the osquery repo root!" -ForegroundColor Red
    exit
  }
  & '.\tools\make-win64-binaries.bat'

  # Listing of artifacts bundled with osquery
  $scriptPath = Get-Location
  $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
  $certs = Join-Path "$chocoPath" 'lib\openssl\local\certs'
  if (-not (Test-Path $certs)) {
    Write-Host "[*] Did not find openssl certs.pem" -ForegroundColor Yellow
  }

  $conf = Join-Path $scriptPath '.\tools\deployment\osquery.example.conf'
  if (-not (Test-Path $conf)) {
    Write-Host "[*] Did not find example configuration" -ForegroundColor Yellow
  }

  $packs = Join-Path $scriptPath '.\packs'
  if (-not (Test-Path $packs)) {
    Write-Host "[*] Did not find example packs" -ForegroundColor Yellow
  }

  $nupkg =
@'
<?xml version="1.0" encoding="utf-8"?>
<!-- Do not remove this test for UTF-8: if “Ω” doesn’t appear as greek uppercase omega letter enclosed in quotation marks, you should use an editor that supports UTF-8, not this one. -->
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>osquery</id>
    <version>
'@
$nupkg += $version
$nupkg +=
@'
</version>
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
$nupkg += "https://github.com/facebook/osquery/releases/tag/$latestFullVersion"
$nupkg +=
@'
</releaseNotes>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
'@
  Copy-Item -Recurse -Force "$scriptPath\tools\deployment\chocolatey\" "$scriptPath\build\"
  Copy-Item -Recurse -Force $packs "$scriptPath\build\packs-examples"
  $packsPath = "$scriptPath\build\packs-examples"
  New-Item -Force -ItemType Directory -Path "$scriptPath\build\chocolatey\tools\bin"
  $buildDir = "$scriptPath\build\windows10\osquery\Release\"
  $clientPath = Join-Path $buildDir 'osqueryi.exe'
  $daemonPath = Join-Path $buildDir 'osqueryd.exe'
  $manageScriptPath = "$scriptPath\tools\manage-osqueryd.ps1"
  $nupkg | Out-File -Encoding "UTF8" "$scriptPath\build\chocolatey\osquery.nuspec"
  if (-not ((Test-Path $clientPath) -or (Test-Path $daemonPath))) {
    Write-Host '[-] Unable to find osquery binaries!  Check the results of the build scripts!' -ForegroundColor Red
    exit
  }

  # This bundles up all of the files we distribute.
  # Issue #2962 - This is where we can bundle additional deploy artifacts.

  7z a "$scriptPath\build\chocolatey\tools\bin\osquery.zip" $clientPath $daemonPath $certs $conf $packsPath $manageScriptPath
  Write-Debug "[+] Creating the chocolatey package for osquery $version"
  Set-Location "$scriptPath\build\chocolatey\"
  choco pack

  Write-Host "[+] Chocolatey Package has been created. Run 'choco push' to push the package to Chocolatey" -ForegroundColor Green

  # TODO: Consider putting this into another powershell script 'push-chocolatey-package.ps1'
  #Write-Debug "[+] Pushing osquery-$version.nupkg to chocolatey"
  #choco push
}

$null = Main
