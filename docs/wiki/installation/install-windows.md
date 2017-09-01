As of osquery 1.8.2+ the Windows builds are feature-complete but provide a limited set of tables compared to macOS and Linux.

## Installing osquery on Windows
We recommend installing Windows via the Chocolatey package system however a helper script for generating an **MSI** installer is available at `tools\deployment\make_windows_package.ps1` by invoking with an 'msi' parameter. Further manual installation instructions are detailed below for those needing more custom deployment options.

### Installing with Chocolatey
Each osquery tag (stable release) is published to **chocolatey** for our supported versions: [https://chocolatey.org/packages/osquery/](https://chocolatey.org/packages/osquery/)

By default Chocolatey will install the binaries, example packs, example configuration, and an OpenSSL certificate bundle to `C:\ProgramData\osquery` and nothing more. You can pass Chocolatey the `--params='/InstallService'` flag or make use of osquery's `--install` flag with `C:\ProgramData\osquery\osqueryd\osqueryd.exe --install` to install a Windows system service for the **osqueryd** daemon.

### Installing osquery via the MSI package
While we currently are not hosting any MSI packages, we've included a small script that will generate for you an MSI package capable of installing osquery on hosts as mentioned above. Running `.\tools\deployment\make_windows_package.ps1 'msi'` from the source root will generate you a standalone MSI package along with the example packs, configuration, and OpenSSL cert bundle. **Note** however, that this MSI bundle does not currently deploy the "safe" folder permissions required for the daemon to run, and thus one will need to make use of the Powershell scripts below to set the correct permissions on the daemon and extensions folders. These restrictive safe permissions will be relaxed in a future release but this work is currently left as [a TODO item](https://github.com/facebook/osquery/issues/3704).

### Installing Manually
To get osquery running as a SYSTEM level service on Windows, one must ensure two things:

1.) osqueryd.exe is running with 'safe' permissions, and
2.) The Windows service control manager has all of the correct information for running the daemon

Safe permissions for the `osqueryd.exe` daemon entail an explicit Deny-Write ACL placed on the directory in which `osqueryd.exe` exists inheriting to child objects and containers. The recommended way to set these ACLs is with Powershell, and we've written a helper function to handle these permissions. To do so, `.` source the file and call the function as follows:
```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  . .\tools\provision\chocolatey\osquery_utils.ps1
C:\Users\Thor\work\repos\osquery [master ≡]
λ  Set-DenyWriteAcl C:\ProgramData\osquery\osqueryd\ 'Add'
True
```
If you'd prefer to manually set the permissions the explicit invocations for Powershell are:
```
$targetDir = 'C:\ProgramData\osquery\osqueryd'
$acl = Get-Acl $targetDir
$inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$permType = [System.Security.AccessControl.AccessControlType]::Deny

$worldSIDObj = New-Object System.Security.Principal.SecurityIdentifier ('S-1-1-0')
$worldUser = $worldSIDObj.Translate( [System.Security.Principal.NTAccount])
$permission = $worldUser.Value, "write", $inheritanceFlag, $propagationFlag, $permType
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl | Set-Acl $targetDir
```
If you'd prefer to avoid using Powershell altogether you can make use of the `icacls.exe` utility provided by Windows as follows:
```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  icacls C:\ProgramData\osquery\osqueryd /deny "Everyone:(OI)(CI)W"
processed file: C:\ProgramData\osquery\osqueryd
Successfully processed 1 files; Failed processing 0 files
```
Now that osquery is properly laid out on disk we need to create a new Windows service to launch and manage the daemon. If you're using Chocolatey you can pass the `--params='/InstallService'` flag during installation to have Chocolatey setup the Windows service for you. In general any method to install a Windows system service will suffice, one simply needs to ensure to specify the `--flagfile` option in the service binary path and give the full paths for the daemon binary and flag file both. Some examples follow:

* To install the service using Powershell we bundle a helper function living in the repo at `.\tools\manage-windows-service.ps1` which can be invoked as follows:
````
/// TODO
````
* If you'd rather use Powershell to manually create the service you can run:
```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  New-Service -Name "osqueryd" -BinaryPathName "C:\ProgramData\osquery\osqueryd\osqueryd.exe --flagfile=C:\ProgramData\osquery\osquery.flags"
```
Lastly, if you'd prefer to use the Windows service utility `sc.exe` you can use:
```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  sc.exe create osqueryd type= own start= auto error= normal binpath= "C:\ProgramData\osquery\osqueryd\osqueryd.exe --flagfile=\ProgramData\osquery\osquery.flags" displayname= 'osqueryd'
```

## Running osquery

Out of the box osquery is runnable via the Chocolatey installation. More commonly however the daemon is configured to be a system service. To set this up, you'll need to install the daemon via the service installation flags as detailed in the steps above, and then provide the daemon with a config file. The simplest way to get **osqueryd** up and running is to rename the `C:\ProgramData\osquery\osquery.example.conf` file provided to `osquery.conf`. Once the configuration file is in place, you can start the Windows service:
* `Start-Service osqueryd` if you're using **Powershell**
* `sc.exe start osqueryd` if you're using **cmd.exe**

We recommend configuring large fleets with Chef or SCCM.

## Managing the daemon service

osquery provides a helper script for [managing the osquery daemon service](https://github.com/facebook/osquery/blob/master/tools/manage-osqueryd.ps1), which is installed to `C:\ProgramData\osquery\manage-osqueryd.ps1`.

## Packaging osquery

If you'd like to create your own osquery Chocolatey package you can run [`.\tools\deployment\make_windows_package.ps1`](https://github.com/facebook/osquery/blob/master/tools/deployment/make_windows_package.ps1).  This script will grab the built binaries, the [`packs`](https://github.com/facebook/osquery/blob/master/packs) directory, the [`osquery.example.conf`](https://github.com/facebook/osquery/blob/master/tools/deployment/osquery.example.conf), and attempt to find the OpenSSL `certs.pem` at `C:\ProgramData\chocolatey\lib\openssl\local\certs`.
