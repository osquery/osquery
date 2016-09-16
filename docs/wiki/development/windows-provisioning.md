# Windows 10 Development Environment Provisioning

The bulk of the development environment provisioning logic is in the `tools\provision.ps1` PowerShell script. It is **not** recommended to directly invoke this script. Instead, run the `tools\make-win64-dev-env.bat` batch script. This provisioning script is used to prepare a clean Windows 10 64 bit operating system into one that is prepared for **osquery** development by downloading and installing the proper tools and dependencies.

Generating the Visual Studio 2015 solution and building the **osquery** binaries is done via the `tools\make-win64-binaries.bat` batch script. 

## Initial Assumptions

 * `git` for Windows should be already installed in order to `git clone` the **osquery** repository containing the provisioning script.
 * The machine is running the Windows 10 64 bit operating system with PowerShell 3.0 and later installed
 * No previous instance of Visual Studio 2015 is already installed.
 * The user is running the script as an **Administrator**

## Automated Method (recommended)

 * Open a new *Command Prompt*
 * Execute the following command: `git clone https://github.com/facebook/osquery`
 * Change into the **osquery** root directory: `cd osquery`
 * **As an _Administrator_ with elevated privileges,** run the batch script to provision a Windows 10 64 bit development environment: `tools\make-win64-dev-env.bat`
 * **As an _Administrator_ with elevated privileges,** run the batch script to generate a Visual Studio 2015 and commence building the osquery shell, daemon, and tests: `tools\make-win64-binaries.bat`

## Manual Method
### Generating the Visual Studio 2015 Win64 Solution

 * Open a new *Command Prompt*
 * Execute the following command: `git clone https://github.com/facebook/osquery`
 * Change into the **osquery** root directory: `cd osquery`
 * **As an _Administrator_,** run the batch script to provision a Windows 10 64 bit development environment: `tools\make-win64-dev-env.bat`
 * After completion, create the build folder: `mkdir build\windows10`
 * Change into the recently created build folder: `cd build\windows10`
 * Generate the Visual Studio 2015 solution files: `cmake ..\.. -G "Visual Studio 14 2015 Win64"`
 * There should be a `OSQUERY.sln` in the build folder. Open this with Visual Studio 2015 that is already installed via the provisioning script.

### Building `osqueryd.exe` and `osqueryi.exe`
 
 * **Automated Process**
   * Run `tools\make-win64-binaries.bat` from the `osquery` root directory. This will create the CMake build files and execute `cmake --build` to compile the shell and copy all required DLLs into the shell's output directory.
 * **Manual Process**
   * Open the Visual Studio 2015 solution, `OSQUERY.sln`
   * Select **Release** or **RelWithDebInfo** as the build configuration.
   * For `osqueryd.exe`, build the **daemon** project; `osqueryi.exe`, build the **shell** project
   
## Chocolatey Packages Installed (from official sources)

 * chocolatey (if applicable)
 * 7zip.commandline
 * cmake.portable 3.6.1
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
 * clang-format 3.9.0
 * zlib 1.2.8

## Other Actions

 * Upgrades **python2**'s `pip` package
 * Installs all the Python packages as per **requirements.txt** (possible issue with Vagrant from the thrift Python package)
 * Ensures that `third-party/` git submodules are initialized
