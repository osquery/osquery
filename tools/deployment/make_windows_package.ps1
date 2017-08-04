# We make heavy use of Write-Host, because colors are awesome. #dealwithit.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", '', Scope="Function", Target="*")]
param()

function Main() {
  $working_dir = Get-Location
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
  # Binaries might not be built, let's try to build them quick :)
  if (-not (Test-Path (Join-Path (Get-Location).Path 'build\windows10\osquery\Release'))) {
    & '.\tools\make-win64-binaries.bat'
  }

  # Listing of artifacts bundled with osquery
  $scriptPath = Get-Location
  $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
  $certs = Join-Path "$chocoPath" 'lib\openssl\local\certs'
  if (-not (Test-Path $certs)) {
    Write-Host "[*] Did not find openssl certs.pem" -ForegroundColor Yellow
  }

  $conf = Join-Path $scriptPath 'tools\deployment\osquery.example.conf'
  if (-not (Test-Path $conf)) {
    Write-Host "[*] Did not find example configuration" -ForegroundColor Yellow
  }

  $packs = Join-Path $scriptPath 'packs'
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

  $chocoBuildPath = "$scriptPath\build\chocolatey"
  $osqueryChocoPath = "$chocoBuildPath\osquery"
  New-Item -Force -ItemType Directory -Path "$osqueryChocoPath\tools\bin"
  Copy-Item -Recurse -Force "$scriptPath\tools\deployment\chocolatey\tools" "$osqueryChocoPath"
  Copy-Item -Recurse -Force "$scriptPath\tools\provision\chocolatey\osquery_utils.ps1" "$osqueryChocoPath\tools\osquery_utils.ps1"

  $buildDir = "$scriptPath\build\windows10\osquery\Release\"
  $clientPath = Join-Path $buildDir 'osqueryi.exe'
  $daemonPath = Join-Path $buildDir 'osqueryd.exe'
  $mgmtScript = "$scriptPath\tools\manage-osqueryd.ps1"
  $nupkg | Out-File -Encoding "UTF8" "$osqueryChocoPath\osquery.nuspec"
  if (-not ((Test-Path $clientPath) -or (Test-Path $daemonPath))) {
    Write-Host '[-] Unable to find osquery binaries!  Check the results of the build scripts!' -ForegroundColor Red
    exit
  }

  # This bundles up all of the files we distribute.
  7z a "$osqueryChocoPath\tools\bin\osquery.zip" $clientPath $daemonPath $certs $conf $packs $mgmtScript
  Write-Debug "[+] Creating the chocolatey package for osquery $version"
  Set-Location "$osqueryChocoPath"
  choco pack

  Write-Host "[+] Chocolatey Package written to $osqueryChocoPath" -ForegroundColor Green
  Set-Location $working_dir
}

$null = Main
