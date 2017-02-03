. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\\osquery_utils.ps1"

$packageName = 'osquery'
$serviceName = 'osqueryd'
$serviceDescription = 'osquery daemon service'
$progData =  [System.Environment]::GetEnvironmentVariable('ProgramData')
$targetFolder = Join-Path $progData 'osquery'
$daemonFolder = Join-Path $targetFolder 'osqueryd'
$logFolder = Join-Path $targetFolder 'log'
$targetDaemonBin = Join-Path $targetFolder 'osqueryd.exe'
$destDaemonBin = Join-Path $daemonFolder 'osqueryd.exe'
$destClientBin = Join-Path $targetFolder 'osqueryi.exe'
$packageParameters = $env:chocolateyPackageParameters
$arguments = @{}

# Now parse the packageParameters using good old regular expression
if ($packageParameters) {
  $match_pattern = "\/(?<option>([a-zA-Z]+)):(?<value>([`"'])?([a-zA-Z0-9- _\\:\.]+)([`"'])?)|\/(?<option>([a-zA-Z]+))"
  $option_name = 'option'
  $value_name = 'value'

  if ($packageParameters -match $match_pattern ) {
    $results = $packageParameters | Select-String $match_pattern -AllMatches
    $results.matches | ForEach-Object {
      $arguments.Add(
        $_.Groups[$option_name].Value.Trim(),
        $_.Groups[$value_name].Value.Trim())
    }
  } else {
    Throw "Package Parameters were found but were invalid (REGEX Failure)"
  }
  if ($arguments.ContainsKey("InstallService")) {
    $installService = $true
  }
} else {
  Write-Debug "No Package Parameters Passed in"
}

New-Item -Force -Type directory -Path $daemonFolder
New-Item -Force -Type directory -Path $logFolder
$packagePath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\\bin\\osquery.zip"
Get-ChocolateyUnzip -FileFullPath $packagePath -Destination $targetFolder

# In order to run osqueryd as a service, we need to have a folder that has a
# Deny Write ACL to everyone.
Move-Item -Force -Path $targetDaemonBin -Destination $destDaemonBin
Set-DenyWriteAcl $daemonFolder 'Add'

if ($installService -and (-not (Get-Service $serviceName -ErrorAction SilentlyContinue))) {
  Write-Debug '[+] Installing osquery daemon service.'
  # If the 'install' parameter is passed, we create a Windows service with
  # the flag file in the default location in \ProgramData\osquery\
  New-Service -Name $serviceName -BinaryPathName "$destDaemonBin --flagfile=\ProgramData\osquery\osquery.flags" -DisplayName $serviceName -Description $serviceDescription -StartupType Automatic
}

# Add osquery binary path to machines path for ease of use.
$oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if (-not ($oldPath -imatch [regex]::escape($targetFolder))) {
  $newPath = $oldPath
  if ($oldPath[-1] -eq ';') {
    $newPath = $newPath + $targetFolder
  } else {
    $newPath = $newPath + ';' + $targetFolder
  }
  [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}

if (Test-Path $targetFolder) {
  Write-Output "osquery was successfully installed to $targetFolder."
} else {
  Write-Output 'There was an error installing osquery.'
}
