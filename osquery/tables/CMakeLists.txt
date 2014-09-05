if(APPLE)
  ADD_LIBRARY(osquery_tables_objc
    ../core/darwin/NSProcessInfo+PECocoaBackports.mm
    system/darwin/osx_version.mm
  )
  TARGET_LINK_LIBRARIES(osquery_tables_objc "-framework Foundation")
  SET_TARGET_PROPERTIES(osquery_tables_objc PROPERTIES COMPILE_FLAGS "-x objective-c++ -fobjc-arc")

  ADD_LIBRARY(osquery_tables_darwin
    networking/interfaces.cpp
    networking/listening_ports.cpp
    networking/routes.cpp
    networking/utils.cpp
    system/darwin/apps.cpp
    system/darwin/ca_certs.cpp
    system/darwin/firewall.cpp
    system/darwin/kextstat.cpp
    system/darwin/launchd.cpp
    system/darwin/nvram.cpp
    system/processes.cpp
  )
  TARGET_LINK_LIBRARIES(osquery_tables_darwin boost_filesystem)
  TARGET_LINK_LIBRARIES(osquery_tables_darwin osquery_database)
  TARGET_LINK_LIBRARIES(osquery_tables_darwin osquery_filesystem)
  TARGET_LINK_LIBRARIES(osquery_tables_darwin "-framework IOKit -framework CoreFoundation -framework Security")
  SET_TARGET_PROPERTIES(osquery_tables_darwin PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
else()
  ADD_LIBRARY(osquery_tables_linux
    system/linux/kernel_modules.cpp
  )
  TARGET_LINK_LIBRARIES(osquery_tables_linux boost_filesystem)
  TARGET_LINK_LIBRARIES(osquery_tables_linux osquery_database)
  TARGET_LINK_LIBRARIES(osquery_tables_linux osquery_filesystem)
  SET_TARGET_PROPERTIES(osquery_tables_linux PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})  
endif()

FILE(GLOB table_sources
  "generated/*.cpp"
  "manual/*.cpp"
)

ADD_LIBRARY(osquery_tables
  registry.cpp
  ${table_sources}
  networking/etc_hosts.cpp
  utility/time.cpp
)

TARGET_LINK_LIBRARIES(osquery_tables glog)
TARGET_LINK_LIBRARIES(osquery_tables osquery_core)
TARGET_LINK_LIBRARIES(osquery_tables osquery_database)
TARGET_LINK_LIBRARIES(osquery_tables osquery_filesystem)
TARGET_LINK_LIBRARIES(osquery_tables osquery_sqlite)
if(APPLE)
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_objc)
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_darwin)
  TARGET_LINK_LIBRARIES(osquery_tables "-Wl,-all_load")
else()
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_linux)
endif()
SET_TARGET_PROPERTIES(osquery_tables PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})

ADD_EXECUTABLE(etc_hosts_tests networking/etc_hosts_tests.cpp)
TARGET_LINK_LIBRARIES(etc_hosts_tests gtest)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_tables)
SET_TARGET_PROPERTIES(etc_hosts_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
ADD_TEST(etc_hosts_tests etc_hosts_tests)

if(APPLE)
  ADD_EXECUTABLE(apps_tests system/darwin/apps_tests.cpp)
  TARGET_LINK_LIBRARIES(apps_tests gtest)
  TARGET_LINK_LIBRARIES(apps_tests osquery_tables)
  SET_TARGET_PROPERTIES(apps_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
  ADD_TEST(apps_tests apps_tests)

  ADD_EXECUTABLE(ca_certs_tests system/darwin/ca_certs_tests.cpp)
  TARGET_LINK_LIBRARIES(ca_certs_tests gtest)
  TARGET_LINK_LIBRARIES(ca_certs_tests osquery_tables)
  SET_TARGET_PROPERTIES(ca_certs_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
  ADD_TEST(ca_certs_tests ca_certs_tests)

  ADD_EXECUTABLE(firewall_tests system/darwin/firewall_tests.cpp)
  TARGET_LINK_LIBRARIES(firewall_tests gtest)
  TARGET_LINK_LIBRARIES(firewall_tests osquery_tables)
  SET_TARGET_PROPERTIES(firewall_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
  ADD_TEST(firewall_tests firewall_tests)

  ADD_EXECUTABLE(launchd_tests system/darwin/launchd_tests.cpp)
  TARGET_LINK_LIBRARIES(launchd_tests gtest)
  TARGET_LINK_LIBRARIES(launchd_tests osquery_tables)
  SET_TARGET_PROPERTIES(launchd_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
  ADD_TEST(launchd_tests launchd_tests)
endif()
