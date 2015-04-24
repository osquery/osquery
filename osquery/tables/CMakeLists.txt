if(APPLE)
  file(GLOB OSQUERY_OBJC_TABLES "*/darwin/*.mm")
  ADD_OSQUERY_OBJCXX_LIBRARY(FALSE osquery_tables_objc
    ${OSQUERY_OBJC_TABLES}
  )

  file(GLOB OSQUERY_DARWIN_TABLES "*/darwin/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_darwin
    ${OSQUERY_DARWIN_TABLES}
  )

  ADD_OSQUERY_LINK(FALSE "-framework CoreFoundation")
  ADD_OSQUERY_LINK(FALSE "-framework Security")
  ADD_OSQUERY_LINK(FALSE "-framework OpenDirectory")
  ADD_OSQUERY_LINK(FALSE "-framework DiskArbitration")
elseif(FREEBSD)
  file(GLOB OSQUERY_FREEBSD_TABLES "*/freebsd/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_freebsd
    ${OSQUERY_FREEBSD_TABLES}
  )
else()
  file(GLOB OSQUERY_LINUX_TABLES "*/linux/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_linux
    ${OSQUERY_LINUX_TABLES}
  )

  if(CENTOS)
    # CentOS specific tables
    file(GLOB OSQUERY_REDHAT_TABLES "*/centos/*.cpp")
    ADD_OSQUERY_LIBRARY(FALSE osquery_tables_redhat
      ${OSQUERY_REDHAT_TABLES}
    )

    ADD_OSQUERY_LINK(FALSE "rpm")
    ADD_OSQUERY_LINK(FALSE "rpmio")
  elseif(UBUNTU)
    # Ubuntu specific tables
    file(GLOB OSQUERY_UBUNTU_TABLES "*/ubuntu/*.cpp")
    ADD_OSQUERY_LIBRARY(FALSE osquery_tables_ubuntu
      ${OSQUERY_UBUNTU_TABLES}
    )

    ADD_OSQUERY_LINK(FALSE "apt-pkg")
    ADD_OSQUERY_LINK(FALSE "dpkg")
  endif()

  ADD_OSQUERY_LINK(FALSE "blkid")
  ADD_OSQUERY_LINK(FALSE "udev")
  ADD_OSQUERY_LINK(FALSE "uuid")
endif()

file(GLOB OSQUERY_CROSS_TABLES "[!u]*/*.cpp")
ADD_OSQUERY_LIBRARY(FALSE osquery_tables
  ${OSQUERY_CROSS_TABLES}
)

file(GLOB OSQUERY_UTILITY_TABLES "utility/*.cpp")
ADD_OSQUERY_LIBRARY(TRUE osquery_tables_utility
  ${OSQUERY_UTILITY_TABLES}
)

file(GLOB OSQUERY_UTILS "utils/*.cpp")
ADD_OSQUERY_LIBRARY(FALSE osquery_utils
  ${OSQUERY_UTILS}
)

ADD_OSQUERY_TEST(FALSE etc_hosts_tests networking/tests/etc_hosts_tests.cpp)
ADD_OSQUERY_TEST(FALSE etc_protocols_tests networking/tests/etc_protocols_tests.cpp)
ADD_OSQUERY_TEST(FALSE yara_tests utils/tests/yara_tests.cpp)
if(APPLE)
  ADD_OSQUERY_TEST(FALSE apps_tests system/darwin/tests/apps_tests.cpp)
  ADD_OSQUERY_TEST(FALSE certificates_tests system/darwin/tests/certificates_tests.cpp)
  ADD_OSQUERY_TEST(FALSE firewall_tests system/darwin/tests/firewall_tests.cpp)
  ADD_OSQUERY_TEST(FALSE launchd_tests system/darwin/tests/launchd_tests.cpp)
endif()
