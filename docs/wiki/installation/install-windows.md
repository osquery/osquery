As of osquery 1.8.2+ the Windows builds are feature-complete but provide a limited set of tables compared to macOS and Linux.

## Chocolatey

Each osquery tag (stable release) is published to **chocolatey** for our supported versions: [https://chocolatey.org/packages/osquery/](https://chocolatey.org/packages/osquery/)

## Installing osquery

By default Chocolatey will install the binaries, example packs, example configuration, and an OpenSSL certificate bundle to `C:\ProgramData\osquery` and nothing more. You can pass Chocolatey the `--params='/InstallService'` flag or make use of osquery's `--install` flag with `C:\ProgramData\osquery\osqueryd\osqueryd.exe --install` to install a Windows system service for the **osqueryd** daemon.

## Running osquery

Out of the box osquery is runnable via the Chocolatey installation. More commonly however the daemon is configured to be a system service. To set this up, you'll need to install the daemon via the service installation flags as detailed in the steps above, and then provide the daemon with a config file. The simplest way to get **osqueryd** up and running is to rename the `C:\ProgramData\osquery\osquery.example.conf` file provided to `osquery.conf`. Once the configuration file is in place, you can start the Windows service:
* `Start-Service osqueryd` if you're using **Powershell**
* `sc.exe start osqueryd` if you're using **cmd.exe**

We recommend configuring large fleets with Chef or SCCM.

## Managing the daemon service

osquery provides a helper script for [managing the osquery daemon service](https://github.com/facebook/osquery/blob/master/tools/manage-osqueryd.ps1), which is installed to `C:\ProgramData\osquery\manage-osqueryd.ps1`.

## Packaging osquery

If you'd like to create your own osquery Chocolatey package you can run [`.\tools\deployment\make_windows_package.ps1`](https://github.com/facebook/osquery/blob/master/tools/deployment/make_windows_package.ps1).  This script will grab the built binaries, the [`packs`](https://github.com/facebook/osquery/blob/master/packs) directory, the [`osquery.example.conf`](https://github.com/facebook/osquery/blob/master/tools/deployment/osquery.example.conf), and attempt to find the OpenSSL `certs.pem` at `C:\ProgramData\chocolatey\lib\openssl\local\certs`.
