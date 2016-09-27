As of osquery 1.8.2+ the Windows builds are feature-complete but provide a limited set of tables compared to OS X and Linux.

## Chocolatey

Each osquery tag (release) is published to **chocolatey** for our supported versions: [https://chocolatey.org/packages/osquery/](https://chocolatey.org/packages/osquery/)

## Running osquery

The default install location is `C:\ProgramData\osquery`. The Chocolatey package will also use the `.\osqueryd.exe`'s `--install` and `--uninstall` optional switches to install an osquery service.

We recommend configuring large fleets with Chef or SCCM.

In the future, the osquery repository will include scripts for creating packages and wrapping a helper [`manage-osqueryd.ps1`](https://github.com/facebook/osquery/blob/master/tools/manage-osqueryd.ps1) tool.