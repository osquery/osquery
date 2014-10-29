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
    system/darwin/nvram.cpp
    system/darwin/processes.cpp
  )

  ADD_OSQUERY_LINK("-framework Foundation")
  ADD_OSQUERY_LINK("-framework IOKit")
  ADD_OSQUERY_LINK("-framework CoreFoundation")
  ADD_OSQUERY_LINK("-framework Security")
  ADD_OSQUERY_LINK("-framework OpenDirectory")
else()
  ADD_OSQUERY_LIBRARY(osquery_tables_linux
    events/linux/passwd_changes.cpp
    networking/linux/routes.cpp
    system/linux/kernel_modules.cpp
    system/linux/processes.cpp
    system/linux/users.cpp
    system/linux/groups.cpp
  )
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
  system/last.cpp
  system/bash_history.cpp
  system/suid_bin.cpp
  base.h
)

ADD_OSQUERY_TEST(etc_hosts_tests networking/etc_hosts_tests.cpp)
if(APPLE)
  ADD_OSQUERY_TEST(apps_tests system/darwin/apps_tests.cpp)
  ADD_OSQUERY_TEST(ca_certs_tests system/darwin/ca_certs_tests.cpp)
  ADD_OSQUERY_TEST(firewall_tests system/darwin/firewall_tests.cpp)
  ADD_OSQUERY_TEST(launchd_tests system/darwin/launchd_tests.cpp)
endif()
