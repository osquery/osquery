## Kernel (OS X only)

Currently an kernel extension is under development for OS X that will create new data feeds for event based information.

WARNING:  This is currently under development.

## Building on OS X for local loading (not recommended)

Working in the kernel directory:

First disable signature verification on the machine by running `make disable-signing` a reboot is required for this to take effect.  CAUTION: this lowers the security of your system.  It is better to have your kernel extensions signed.

Once kernel extension signature verification is disabled, just `make` the kernel extension.  It can then be loaded and unloaded with `make load` and `make unload`.  For permanent installations it should be added to the systems startup kernel extensions.

## Building on OS X for a debugging target machine (recommended)

# Debugging environment setup.
- Create an OS X VM to act as the target machine.
- Make the osquery directory a shared folder between host and VM.
- Get a [kernel debug kit](https://developer.apple.com/downloads/).
- Install it on both the target machine VM and the host debugging machine.
- Run make targets to configure the target machine and the debugger machine.
  - `make configure-target`   (on VM, requires a reboot)
  - `make configure-debugger` (on host)
- Launch debugger on host using the `make db` target this loads the kernel symbols and commands.
- Connect to VM using the `kdp-remote <ip-address>` command.
- Once the VM is booted ssh in and load the kext by running the `make load` target.

