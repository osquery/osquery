# Windows 10 Provisioning Script

The PowerShell script `provision.ps1` is used to prepare a clean Windows 10 64 bit machine into one that is ready of **osquery** development on Windows. However, the script does _not_ automate the generation of the Visual Studio 2015 solution nor performs the build process.

## Initial Assumptions

 * `git` for Windows should be already installed in order to `git clone` the **osquery** repository containing the provisioning script.
 * The machine is running the Windows 10 64 bit operating system with PowerShell
 * No previous instance of Visual Studio 2015 is already installed.
 * The user is running the script as an **Administrator**

## Generating the Visual Studio 2015 Win64 Solution

 * Open a new *Command Prompt*
 * Execute the following command: `git clone https://github.com/facebook/osquery`
 * Change into the **osquery** root directory: `cd osquery`
 * **As an _Administrator_,** run the batch script to provision a Windows 10 64 bit development environment: `tools\make-win64-dev-env.bat`
 * After completion, create the build folder: `mkdir build\windows10`
 * Change into the recently created build folder: `cd build\windows10`
 * Generate the Visual Studio 2015 solution files: `cmake ..\.. -G "Visual Studio 14 2015 Win64"`
 * There should be a `OSQUERY.sln` in the build folder. Open this with Visual Studio 2015 that is already installed via the provisioning script.

## Building `osqueryd.exe` and `osqueryi.exe`
 
 * Open the Visual Studio 2015 solution, `OSQUERY.sln`
 * Select **Release** or **RelWithDebInfo** as the build configuration.
 * For `osqueryd.exe`, build the **daemon** project; `osqueryi.exe`, build the **shell** project
 * After the build succeeds, copy the following DLLs to the directory containing `osqueryd.exe`/`osqueryi.exe` (usually in `build\windows10\osquery\Release` or `build\windows10\osquery\RelWithDebInfo`)
   * `%ChocolateyInstall%\lib\openssl\local\bin\libeay32.dll`
   * `%ChocolateyInstall%\lib\openssl\local\bin\ssleay32.dll`
   * `%ChocolateyInstall%\lib\glog\local\bin\glog.dll`
   * `%ChocolateyInstall%\lib\linenoise-ng\local\bin\linenoise.dll`
   
## Chocolatey Packages Installed (from official sources)

 * chocolatey (if applicable)
 * 7zip.commandline
 * cmake.portable 3.5.0
 * python2 2.7.11
 * visualstudio2015community (with a custom deployment XML ensuring C/C++ toolchain is installed)
 * thrift 0.9.3 (as a dependency from one of our private packages)

## Chocolatey Packages Installed (from private sources)

Official chocolatey sources do not provide everything we need. In order to mitigate this issue, we built our own custom Chocolatey packages with the required development libraries needed to build *osquery*.

 * boost-msvc14 1.59.0
 * bzip2 1.0.6
 * doxygen 1.8.11
 * gflags-dev 2.1.2
 * glog 0.3.4
 * openssl 1.0.2
 * rocksdb 4.4
 * snappy-msvc 1.1.1.8
 * thrift-dev 0.9.3
 * cpp-netlib 0.12.0
 * linenoise-ng 1.0.0

## Other Actions

 * Upgrades **python2**'s `pip` package
 * Installs all the Python packages as per **requirements.txt** (possible issue with Vagrant from the thrift Python package)
 * Ensures that `third-party/` git submodules are initialized
