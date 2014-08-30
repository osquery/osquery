if(APPLE)
  ADD_LIBRARY(osquery_tables_objc
    ../core/osx/NSProcessInfo+PECocoaBackports.mm
    system/osx_version.mm
  )
  TARGET_LINK_LIBRARIES(osquery_tables_objc "-framework Foundation")
  SET_TARGET_PROPERTIES(osquery_tables_objc PROPERTIES COMPILE_FLAGS "-x objective-c++ -fobjc-arc")

  ADD_LIBRARY(osquery_tables_osx
    networking/interfaces.cpp
    networking/listening_ports.cpp
    networking/routes.cpp
    networking/utils.cpp
    system/apps.cpp
    system/cacerts.cpp
    system/firewall.cpp
    system/kextstat.cpp
    system/launchd.cpp
    system/nvram.cpp
    system/processes.cpp
  )
  TARGET_LINK_LIBRARIES(osquery_tables_osx boost_filesystem)
  TARGET_LINK_LIBRARIES(osquery_tables_osx osquery_database)
  TARGET_LINK_LIBRARIES(osquery_tables_osx osquery_filesystem)
  TARGET_LINK_LIBRARIES(osquery_tables_osx "-framework IOKit -framework CoreFoundation -framework Security")
  SET_TARGET_PROPERTIES(osquery_tables_osx PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
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
TARGET_LINK_LIBRARIES(osquery_tables osquery_sqlite)
if(APPLE)
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_objc)
  TARGET_LINK_LIBRARIES(osquery_tables osquery_tables_osx)
endif()
TARGET_LINK_LIBRARIES(osquery_tables "-Wl,-all_load")
SET_TARGET_PROPERTIES(osquery_tables PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_EXECUTABLE(etc_hosts_tests networking/etc_hosts_tests.cpp)
TARGET_LINK_LIBRARIES(etc_hosts_tests gtest)
TARGET_LINK_LIBRARIES(etc_hosts_tests glog)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_core)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_database)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_filesystem)
TARGET_LINK_LIBRARIES(etc_hosts_tests osquery_tables)
SET_TARGET_PROPERTIES(etc_hosts_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
