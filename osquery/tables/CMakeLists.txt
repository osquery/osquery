if(APPLE)
  file(GLOB OSQUERY_OBJC_TABLES "*/darwin/*.mm")
  ADD_OSQUERY_OBJCXX_LIBRARY(FALSE osquery_tables_objc
    ${OSQUERY_OBJC_TABLES}
  )

  file(GLOB OSQUERY_DARWIN_TABLES "*/darwin/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_darwin
    ${OSQUERY_DARWIN_TABLES}
  )

  file(GLOB OSQUERY_DARWIN_TABLES_TESTS "*/darwin/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_DARWIN_TABLES_TESTS})

  ADD_OSQUERY_LINK(FALSE "-framework CoreFoundation")
  ADD_OSQUERY_LINK(FALSE "-framework Security")
  ADD_OSQUERY_LINK(FALSE "-framework OpenDirectory")
  ADD_OSQUERY_LINK(FALSE "-framework DiskArbitration")
elseif(FREEBSD)
  file(GLOB OSQUERY_FREEBSD_TABLES "*/freebsd/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_freebsd
    ${OSQUERY_FREEBSD_TABLES}
  )

  file(GLOB OSQUERY_FREEBSD_TABLES_TESTS "*/freebsd/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_FREEBSD_TABLES_TESTS})
else()
  file(GLOB OSQUERY_LINUX_TABLES "*/linux/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_tables_linux
    ${OSQUERY_LINUX_TABLES}
  )

  file(GLOB OSQUERY_LINUX_TABLES_TESTS "*/linux/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_LINUX_TABLES_TESTS})

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
  ADD_OSQUERY_LINK(FALSE "cryptsetup")
  ADD_OSQUERY_LINK(FALSE "udev")
  ADD_OSQUERY_LINK(FALSE "uuid")
endif()

file(GLOB OSQUERY_CROSS_TABLES "[!ue]*/*.cpp")
ADD_OSQUERY_LIBRARY(FALSE osquery_tables
  ${OSQUERY_CROSS_TABLES}
)

file(GLOB OSQUERY_CROSS_TABLES_TESTS "[!u]*/tests/*.cpp")
ADD_OSQUERY_TABLE_TEST(${OSQUERY_CROSS_TABLES_TESTS})

file(GLOB OSQUERY_UTILITY_TABLES "utility/*.cpp")
ADD_OSQUERY_LIBRARY(TRUE osquery_tables_utility
  ${OSQUERY_UTILITY_TABLES}
)

if(NOT FREEBSD)
  file(GLOB OSQUERY_UTILS "utils/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_utils
    ${OSQUERY_UTILS}
  )

  file(GLOB OSQUERY_UTILS_TESTS "utils/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_UTILS_TESTS})
endif()
