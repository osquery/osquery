if(APPLE)
  file(GLOB OSQUERY_OBJC_TABLES "*/darwin/*.mm")
  ADD_OSQUERY_OBJCXX_LIBRARY_ADDITIONAL(osquery_tables_objc
    ${OSQUERY_OBJC_TABLES}
  )

  file(GLOB OSQUERY_DARWIN_TABLES "*/darwin/*.cpp")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables_darwin
    ${OSQUERY_DARWIN_TABLES}
  )

  file(GLOB OSQUERY_DARWIN_TABLES_TESTS "*/darwin/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_DARWIN_TABLES_TESTS})

  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreFoundation")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework Security")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework OpenDirectory")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework DiskArbitration")

  ADD_OSQUERY_LINK_ADDITIONAL("archive")
  ADD_OSQUERY_LINK_ADDITIONAL("magic")
elseif(FREEBSD)
  file(GLOB OSQUERY_FREEBSD_TABLES "*/freebsd/*.cpp")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables_freebsd
    ${OSQUERY_FREEBSD_TABLES}
  )

  file(GLOB OSQUERY_FREEBSD_TABLES_TESTS "*/freebsd/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_FREEBSD_TABLES_TESTS})

  ADD_OSQUERY_LINK_ADDITIONAL("procstat")
  ADD_OSQUERY_LINK_ADDITIONAL("util")
  ADD_OSQUERY_LINK_ADDITIONAL("kvm")
  ADD_OSQUERY_LINK_ADDITIONAL("elf")
else()
  file(GLOB OSQUERY_LINUX_TABLES "*/linux/*.cpp")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables_linux
    ${OSQUERY_LINUX_TABLES}
  )

  file(GLOB OSQUERY_LINUX_TABLES_TESTS "*/linux/tests/*.cpp")
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_LINUX_TABLES_TESTS})

  if(CENTOS OR RHEL OR AMAZON)
    # CentOS specific tables
    file(GLOB OSQUERY_REDHAT_TABLES "*/centos/*.cpp")
    ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables_redhat
      ${OSQUERY_REDHAT_TABLES}
    )

    ADD_OSQUERY_LINK_ADDITIONAL("rpm rpmio")
  elseif(UBUNTU)
    # Ubuntu specific tables
    file(GLOB OSQUERY_UBUNTU_TABLES "*/ubuntu/*.cpp")
    ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables_ubuntu
      ${OSQUERY_UBUNTU_TABLES}
    )

	# libdpkg API is volitile and suffers breaking changes. We need to find and pass in the libdpkg
	# version via pkg-config
	find_package(Libdpkg REQUIRED)
	add_definitions(-DLIBDPKG_VERSION=${LIBDPKG_VERSION_NUMBER})

    ADD_OSQUERY_LINK_ADDITIONAL("apt-pkg dpkg")
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("blkid")
  ADD_OSQUERY_LINK_ADDITIONAL("cryptsetup libdevmapper.so libgcrypt.so")
  ADD_OSQUERY_LINK_ADDITIONAL("libuuid.so")
  ADD_OSQUERY_LINK_ADDITIONAL("ip4tc")
  ADD_OSQUERY_LINK_ADDITIONAL("libmagic.so")
endif()


file(GLOB OSQUERY_CROSS_APPLICATIONS_TABLES "applications/*.cpp")
file(GLOB OSQUERY_CROSS_SYSTEM_TABLES "system/*.cpp")
file(GLOB OSQUERY_CROSS_NETWORKING_TABLES "networking/*.cpp")
file(GLOB OSQUERY_CROSS_EVENTS_TABLES "events/*.cpp")
ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_tables
  ${OSQUERY_CROSS_APPLICATIONS_TABLES}
  ${OSQUERY_CROSS_SYSTEM_TABLES}
  ${OSQUERY_CROSS_NETWORKING_TABLES}
  ${OSQUERY_CROSS_EVENTS_TABLES}
)

file(GLOB OSQUERY_CROSS_TABLES_TESTS "[!uo]*/tests/*/*.cpp")
file(GLOB OSQUERY_CATEGORY_TABLE_TESTS "[!uo]*/tests/*.cpp")
file(GLOB OSQUERY_TABLE_TESTS "tests/*.cpp")
ADD_OSQUERY_TABLE_TEST(
  ${OSQUERY_CROSS_TABLES_TESTS}
  ${OSQUERY_CATEGORY_TABLE_TESTS}
  ${OSQUERY_TABLE_TESTS}
)

file(GLOB OSQUERY_UTILITY_TABLES "utility/*.cpp")
ADD_OSQUERY_LIBRARY_CORE(osquery_tables_utility
  ${OSQUERY_UTILITY_TABLES}
)

if(NOT FREEBSD)
  file(GLOB OSQUERY_UTILS "other/*.cpp")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_utils
    ${OSQUERY_UTILS}
  )

  file(GLOB OSQUERY_UTILS_TESTS "other/tests/*.cpp")
  ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_UTILS_TESTS})
endif()
