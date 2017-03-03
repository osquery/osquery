# Windows 10 Development Environment Provisioning

The bulk of the development environment provisioning logic is in the `tools\provision.ps1` PowerShell script. It is **not** recommended to directly invoke this script. Instead, run the `tools\make-win64-dev-env.bat` batch script. This provisioning script is used to prepare a clean Windows 10 64 bit operating system into one that is prepared for **osquery** development by downloading and installing the proper tools and dependencies.

Generating the Visual Studio 2015 solution and building the **osquery** binaries is done via the `tools\make-win64-binaries.bat` batch script. 

**Note**: Both batch scripts above need to be run from the repo root, i.e their invocation should be exactly as they appear above. Read '**Build Process**' below for more details on provisioning.

## Initial Assumptions

 * `git` for Windows should be already installed in order to `git clone` the **osquery** repository containing the provisioning script
 * The machine is running the Windows 10 64 bit operating system with PowerShell 3.0 or later installed
 * No previous instance of Visual Studio 2015 is installed
 * The user is running the script as an **Administrator** with elevated privileges

## Build Process

 * Open a new *Command Prompt* as an **Administrator** with elevated privileges
 * Execute the following command: `git clone https://github.com/facebook/osquery`
 * Change into the **osquery** root directory: `cd osquery`
 * Run the batch script to provision a Windows 10 64 bit development environment: `tools\make-win64-dev-env.bat`
 
### Automated Method (recommended)

 * Run the batch script to generate a Visual Studio 2015 solution and commence building the osquery shell, daemon, and tests: `tools\make-win64-binaries.bat`

### Manual Method
#### Generating the Visual Studio 2015 Win64 Solution

 * Create the build folder: `mkdir build\windows10`
 * Change into the recently created build folder: `cd build\windows10`
 * Generate the Visual Studio 2015 solution files: `cmake ..\.. -G "Visual Studio 14 2015 Win64"`
 * There should be a `OSQUERY.sln` in the `build\windows10` folder, open this with Visual Studio 2015

#### Building `osqueryd.exe` and `osqueryi.exe`
 
 * Open the Visual Studio 2015 solution, `OSQUERY.sln`
 * Select **Release** or **RelWithDebInfo** as the build configuration
 * For `osqueryd.exe`, build the **daemon** project; `osqueryi.exe`, build the **shell** project
   
## Chocolatey Packages Installed (from official sources)

 * chocolatey (if applicable)
 * 7zip.commandline
 * cmake.portable 3.6.1
 * python2 2.7.11
 * visualstudio2015community
 * thrift 0.9.3

## Chocolatey Packages Installed (from private sources)

Official chocolatey sources do not provide everything we need. In order to mitigate this issue, we built our own custom Chocolatey packages with the required development libraries (and tools) required to build *osquery*.

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
 * clang-format 3.9.0
 * zlib 1.2.8

**Note:** Depending on your internet connection it can take time for packages to download. A slow internet connection might cause a time-out error. If such an error occurs then increase the value of the execution-time of the `choco install` command.

## Other Actions

 * Upgrades **python2**'s `pip` package
 * Installs all the Python packages as per **requirements.txt** (possible issue with Vagrant from the thrift Python package)
 * Ensures that `third-party/` git submodules are initialized
