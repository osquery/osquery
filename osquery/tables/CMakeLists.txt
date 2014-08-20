FILE(GLOB table_sources
  "generated/*.cpp"
  "manual/*.cpp"
)

ADD_LIBRARY(osquery_tables
  registry.cpp
  ${table_sources}
  examples/example.cpp
  networking/etc_hosts.cpp
  networking/listening_ports.cpp
  networking/routes.cpp
  system/kextstat.cpp
  system/processes.cpp
  system/nvram.cpp
  ../core/osx/NSProcessInfo+PECocoaBackports.mm
  system/osx_version.mm
  system/firewall.cpp
  system/apps.cpp
  system/launchd.cpp
  system/cacerts.cpp
)

TARGET_LINK_LIBRARIES(osquery_tables boost_filesystem)
TARGET_LINK_LIBRARIES(osquery_tables glog)
TARGET_LINK_LIBRARIES(osquery_tables osquery_filesystem)
TARGET_LINK_LIBRARIES(osquery_tables osquery_sqlite)
TARGET_LINK_LIBRARIES(osquery_tables "-Wl,-all_load")
TARGET_LINK_LIBRARIES(osquery_tables "-fobjc-arc -fobjc-link-runtime -framework Foundation -framework IOKit -framework CoreFoundation -framework Security")

ADD_EXECUTABLE(etc_hosts_tests networking/etc_hosts_tests.cpp)
TARGET_LINK_LIBRARIES(etc_hosts_tests gtest)
TARGET_LINK_LIBRARIES(etc_hosts_tests glog)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_core)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_database)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_tables)

ADD_EXECUTABLE(firewall_tests system/firewall_tests.cpp)
TARGET_LINK_LIBRARIES(firewall_tests gtest)
TARGET_LINK_LIBRARIES(firewall_tests glog)
TARGET_LINK_LIBRARIES(firewall_tests osquery_core)
TARGET_LINK_LIBRARIES(firewall_tests osquery_database)
TARGET_LINK_LIBRARIES(firewall_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(firewall_tests osquery_tables)

ADD_EXECUTABLE(apps_tests system/apps_tests.cpp)
TARGET_LINK_LIBRARIES(apps_tests gtest)
TARGET_LINK_LIBRARIES(apps_tests glog)
TARGET_LINK_LIBRARIES(apps_tests osquery_core)
TARGET_LINK_LIBRARIES(apps_tests osquery_database)
TARGET_LINK_LIBRARIES(apps_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(apps_tests osquery_tables)

ADD_EXECUTABLE(launchd_tests system/launchd_tests.cpp)
TARGET_LINK_LIBRARIES(launchd_tests gtest)
TARGET_LINK_LIBRARIES(launchd_tests glog)
TARGET_LINK_LIBRARIES(launchd_tests osquery_core)
TARGET_LINK_LIBRARIES(launchd_tests osquery_database)
TARGET_LINK_LIBRARIES(launchd_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(launchd_tests osquery_tables)

ADD_EXECUTABLE(cacerts_tests system/cacerts_tests.cpp)
TARGET_LINK_LIBRARIES(cacerts_tests gtest)
TARGET_LINK_LIBRARIES(cacerts_tests glog)
TARGET_LINK_LIBRARIES(cacerts_tests osquery_core)
TARGET_LINK_LIBRARIES(cacerts_tests osquery_database)
TARGET_LINK_LIBRARIES(cacerts_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(cacerts_tests osquery_tables)
TARGET_LINK_LIBRARIES(osquery_tables "-framework CoreFoundation -framework Security")
