SET(OSQUERY_CORE_TABLE_TARGETS "")

if(APPLE)
  ADD_LIBRARY(osquery_tables_objc OBJECT
    ../core/darwin/NSProcessInfo+PECocoaBackports.mm
    ../core/darwin/NSProcessInfo+PECocoaBackports.h
    ../core/darwin/PECocoaBackportsGlobal.h
    system/darwin/osx_version.mm
  )

  ADD_OSQUERY_LINK("-framework Foundation")
  SET_OSQUERY_COMPILE(osquery_tables_objc "-x objective-c++ -fobjc-arc")

  list(APPEND OSQUERY_CORE_TABLE_TARGETS $<TARGET_OBJECTS:osquery_tables_objc>)

  ADD_LIBRARY(osquery_tables_darwin OBJECT
    networking/darwin/interfaces.cpp
    networking/darwin/listening_ports.cpp
    networking/darwin/routes.cpp
    system/darwin/apps.cpp
    system/darwin/ca_certs.cpp
    system/darwin/firewall.h
    system/darwin/firewall.cpp
    system/darwin/kextstat.cpp
    system/darwin/launchd.cpp
    system/darwin/nvram.cpp
    system/darwin/processes.cpp
    system/last.cpp
  )

  ADD_OSQUERY_LINK("-framework IOKit")
  ADD_OSQUERY_LINK("-framework CoreFoundation")
  ADD_OSQUERY_LINK("-framework Security")
  SET_OSQUERY_COMPILE(osquery_tables_darwin)

  LIST(APPEND OSQUERY_CORE_TABLE_TARGETS $<TARGET_OBJECTS:osquery_tables_darwin>)
else()
  ADD_LIBRARY(osquery_tables_linux OBJECT
    networking/linux/routes.cpp
    system/linux/kernel_modules.cpp
    system/linux/processes.cpp
  )

  ADD_OSQUERY_LINK("procps")
  SET_OSQUERY_COMPILE(osquery_tables_linux)

  LIST(APPEND OSQUERY_CORE_TABLE_TARGETS $<TARGET_OBJECTS:osquery_tables_linux>)
endif()

# Add the targets from above to libosquery (may change with plugins)
ADD_OSQUERY_LIB("${OSQUERY_CORE_TABLE_TARGETS}")

FILE(GLOB table_sources
  "generated/*.cpp"
  "manual/*.cpp"
)

ADD_LIBRARY(osquery_tables OBJECT
  ${table_sources}
  networking/utils.cpp
  networking/etc_hosts.cpp
  utility/time.cpp
  base.h
)

SET_OSQUERY_COMPILE(osquery_tables)

ADD_LIBRARY(osquery_tables_testing
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_sqlite>
  $<TARGET_OBJECTS:osquery_registry>
  $<TARGET_OBJECTS:osquery_filesystem>
  $<TARGET_OBJECTS:osquery_tables>
  ${OSQUERY_CORE_TABLE_TARGETS}
  ${OSQUERY_LIB_ADDITIONAL_OBJECTS}
)

ADD_OSQUERY_TEST(etc_hosts_tests networking/etc_hosts_tests.cpp
  osquery_tables_testing)

if(APPLE)
  ADD_OSQUERY_TEST(apps_tests system/darwin/apps_tests.cpp
    osquery_tables_testing)

  ADD_OSQUERY_TEST(ca_certs_tests system/darwin/ca_certs_tests.cpp
    osquery_tables_testing)

  ADD_OSQUERY_TEST(firewall_tests system/darwin/firewall_tests.cpp
    osquery_tables_testing)

  ADD_OSQUERY_TEST(launchd_tests system/darwin/launchd_tests.cpp
    osquery_tables_testing)
endif()
