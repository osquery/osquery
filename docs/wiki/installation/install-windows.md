As of osquery 1.8.2+ the Windows builds are feature-complete but provide a limited set of tables compared to macOS and Linux.

## Installing osquery on Windows

We recommend installing Windows via the Chocolatey package system however a helper script for generating an **MSI** installer is available at `tools\deployment\make_windows_package.ps1` by invoking with an 'msi' parameter. Further manual installation instructions are detailed below for those needing more custom deployment options.

### Installing with Chocolatey

Each osquery tag (stable release) is published to **chocolatey** for our supported versions: [https://chocolatey.org/packages/osquery/](https://chocolatey.org/packages/osquery/)

By default Chocolatey will install the binaries, example packs, example configuration, and an OpenSSL certificate bundle to `C:\ProgramData\osquery` and nothing more. You can pass Chocolatey the `--params='/InstallService'` flag or make use of osquery's `--install` flag with `C:\ProgramData\osquery\osqueryd\osqueryd.exe --install` to install a Windows SYSTEM level service for the **osqueryd** daemon.

### Installing osquery via the MSI package

While we currently are not hosting any MSI packages, we've included a small script that will generate for you an MSI package capable of installing osquery on hosts as mentioned above. Running `.\tools\deployment\make_windows_package.ps1 'msi'` from the source root will generate you a standalone MSI package along with the example packs, configuration, and OpenSSL cert bundle.

### Installing Manually

To get osquery running as a SYSTEM level service on Windows, one must ensure two things:

1. `osqueryd.exe` is running with safe permissions
2. The Windows service control manager has all of the correct information for running the daemon

The `osqueryd.exe` daemon is considered safe if the binary and the directory in which the binary resides do not allow non-privileged write accesses and both are owned by either the Administrators group or the SYSTEM account.

The recommended way to set these ACLs is with Powershell and we've written a helper function to handle these permissions. To do so, `.` source the file and call the function as follows:

```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  . .\tools\provision\chocolatey\osquery_utils.ps1
C:\Users\Thor\work\repos\osquery [master ≡]
λ  Set-SafePermissions C:\ProgramData\osquery\osqueryd\
True
```

If you'd prefer to manually set the permissions check the `C:\ProgramData\osquery\osqueryd` directory and ensure that no users or groups have write permissions with the exception of the Administrators group or the SYSTEM account. Read and execute permissions are expected and safe so also ensure the Users group has both.

Now that osquery is properly laid out on disk we need to create a new Windows service to launch and manage the daemon. If you're using Chocolatey you can pass the `--params='/InstallService'` flag during installation to have Chocolatey setup the Windows service for you. In general any method to install a Windows system service will suffice, one simply needs to ensure to specify the `--flagfile` option in the service binary path and give the full paths for the daemon binary and flag file both. Some examples follow:

* To install the service using Powershell we bundle a helper function living in the repo at `.\tools\manage-windows-service.ps1` which can be invoked as follows:

````
C:\ProgramData\osquery
λ  .\manage-osqueryd.ps1 -install -startupArgs C:\ProgramData\osquery\osquery.flags
````

* If you'd rather use Powershell to manually create the service you can run:

```
C:\Users\Thor\work\repos\osquery [master ≡]
λ  New-Service -Name "osqueryd" -BinaryPathName "C:\ProgramData\osquery\osqueryd\osqueryd.exe --flagfile=C:\ProgramData\osquery\osquery.flags"
```

* Lastly, if you'd prefer to use the Windows service utility `sc.exe` you can use:

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

## Enabling Windows Event Log support

In order to enable support for the Windows Event Log, you have to install the manifest file. To install and uninstall it manually, you can use the built-in **wevtutil** command:

 * **Install**: wevtutil im C:\ProgramData\osquery\osquery.man
 * **Uninstall**: wevtutil um C:\ProgramData\osquery\osquery.man

The same operation can be performed using the osquery manager (C:\ProgramData\osquery\manage-osqueryd.ps1):

 * **Install**: .\manage-osqueryd.ps1 -installWelManifest
 * **Uninstall**: .\manage-osqueryd.ps1 -uninstallWelManifest

The manifest file path can also be overridden using the **-welManifestPath** switch.

To verify that everything has been configured correctly, open the Event Viewer and search for the **osquery** folder under **Applications and Services Logs/Facebook/osquery**.

To instruct osquery to use the channel you just created, change the configuration file to use the **windows_event_log** logger plugin.