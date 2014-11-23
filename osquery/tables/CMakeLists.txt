if(APPLE)
  ADD_OSQUERY_OBJCXX_LIBRARY(osquery_tables_objc
    ../core/darwin/NSProcessInfo+PECocoaBackports.mm
    ../core/darwin/NSProcessInfo+PECocoaBackports.h
    ../core/darwin/PECocoaBackportsGlobal.h
    system/darwin/osx_version.mm
    system/darwin/users.mm
    system/darwin/groups.mm
  )

  ADD_OSQUERY_LIBRARY(osquery_tables_darwin
    events/darwin/passwd_changes.cpp
    networking/darwin/interfaces.cpp
    networking/darwin/listening_ports.cpp
    networking/darwin/routes.cpp
    system/darwin/apps.cpp
    system/darwin/ca_certs.cpp
    system/darwin/firewall.h
    system/darwin/firewall.cpp
    system/darwin/homebrew_packages.cpp
    system/darwin/kextstat.cpp
    system/darwin/launchd.cpp
    system/darwin/mounts.cpp
    system/darwin/nvram.cpp
    system/darwin/processes.cpp
    system/darwin/process_open_files.cpp
    system/darwin/quarantine.cpp
    system/darwin/usb_devices.cpp
    system/darwin/startup_items.cpp
  )

  ADD_OSQUERY_LINK("-framework Foundation")
  ADD_OSQUERY_LINK("-framework IOKit")
  ADD_OSQUERY_LINK("-framework CoreFoundation")
  ADD_OSQUERY_LINK("-framework Security")
  ADD_OSQUERY_LINK("-framework OpenDirectory")
elseif(FREEBSD)
  ADD_OSQUERY_LIBRARY(osquery_tables_freebsd
    events/freebsd/passwd_changes.cpp
    networking/freebsd/routes.cpp
    system/freebsd/processes.cpp
    system/freebsd/users.cpp
    system/freebsd/groups.cpp
  )
else()
  ADD_OSQUERY_LIBRARY(osquery_tables_linux
    events/linux/passwd_changes.cpp
    networking/linux/routes.cpp
    networking/linux/socket_inode.cpp
    networking/linux/port_inode.cpp
    networking/linux/arp_cache.cpp
    system/linux/kernel_modules.cpp
    system/linux/processes.cpp
    system/linux/users.cpp
    system/linux/groups.cpp
    system/linux/mounts.cpp
    system/linux/pci_devices.cpp
    system/linux/block_devices.cpp
  )

  # CentOS specific tables
  ADD_OSQUERY_LIBRARY(osquery_tables_redhat
    system/linux/rpm_packages.cpp
  )

  ADD_OSQUERY_LINK("rpm")
  ADD_OSQUERY_LINK("rpmio")

endif()

FILE(GLOB table_sources
  "generated/*.cpp"
  "manual/*.cpp"
)

ADD_OSQUERY_LIBRARY(osquery_tables
  networking/utils.cpp
  networking/etc_hosts.cpp
  utility/time.cpp
  utility/crontab.cpp
  utility/hash.cpp
  system/cpuid.cpp
  system/last.cpp
  system/bash_history.cpp
  system/suid_bin.cpp
  system/logged_in_users.cpp
  base.h
)

ADD_OSQUERY_TEST(etc_hosts_tests networking/etc_hosts_tests.cpp)
if(APPLE)
  ADD_OSQUERY_TEST(apps_tests system/darwin/apps_tests.cpp)
  ADD_OSQUERY_TEST(ca_certs_tests system/darwin/ca_certs_tests.cpp)
  ADD_OSQUERY_TEST(firewall_tests system/darwin/firewall_tests.cpp)
  ADD_OSQUERY_TEST(launchd_tests system/darwin/launchd_tests.cpp)
endif()
