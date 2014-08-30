FILE(GLOB table_sources
  "generated/*.cpp"
  "manual/*.cpp"
)

if(APPLE)
  ADD_LIBRARY(osquery_tables_objc
    ../core/osx/NSProcessInfo+PECocoaBackports.mm
    system/osx_version.mm
  )
  TARGET_LINK_LIBRARIES(osquery_tables_objc "-framework Foundation")
  SET_TARGET_PROPERTIES(osquery_tables_objc PROPERTIES COMPILE_FLAGS "-x objective-c++ -fobjc-arc")
endif()

ADD_LIBRARY(osquery_tables
  registry.cpp
  ${table_sources}
  networking/utils.cpp
  networking/etc_hosts.cpp
  networking/listening_ports.cpp
  networking/routes.cpp
  networking/interfaces.cpp
  system/kextstat.cpp
  system/processes.cpp
  system/nvram.cpp
  system/firewall.cpp
  system/apps.cpp
  system/launchd.cpp
  system/cacerts.cpp
  utility/time.cpp
)

TARGET_LINK_LIBRARIES(osquery_tables boost_filesystem)
TARGET_LINK_LIBRARIES(osquery_tables glog)
TARGET_LINK_LIBRARIES(osquery_tables osquery_filesystem)
TARGET_LINK_LIBRARIES(osquery_tables osquery_sqlite)
TARGET_LINK_LIBRARIES(osquery_tables "-Wl,-all_load")
if(APPLE)
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_objc)
endif()
SET_TARGET_PROPERTIES(osquery_tables PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
TARGET_LINK_LIBRARIES(osquery_tables "-framework IOKit -framework CoreFoundation -framework Security")

ADD_EXECUTABLE(etc_hosts_tests networking/etc_hosts_tests.cpp)
TARGET_LINK_LIBRARIES(etc_hosts_tests gtest)
TARGET_LINK_LIBRARIES(etc_hosts_tests glog)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_core)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_database)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_tables)
SET_TARGET_PROPERTIES(etc_hosts_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
