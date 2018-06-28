#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# List of table categories
set(TABLE_CATEGORIES
  "applications"
  "events"
  "networking"
  "system"
)

if(NOT SKIP_CARVER)
  list(APPEND TABLE_CATEGORIES "forensic")
endif()

# Apple/Darwin specific and applicable tables.
if(APPLE)
  set(TABLE_PLATFORM "darwin")

  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreFoundation")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreWLAN")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreGraphics")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework Security")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework OpenDirectory")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework DiskArbitration")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework ServiceManagement")

  ADD_OSQUERY_LINK_ADDITIONAL("libresolv.dylib")
  ADD_OSQUERY_LINK_ADDITIONAL("libxar.dylib")
  ADD_OSQUERY_LINK_ADDITIONAL("libcups")
  ADD_OSQUERY_LINK_ADDITIONAL("libiconv")
  ADD_OSQUERY_LINK_ADDITIONAL("libbsm")
endif()

# FreeBSD specific and applicable tables.
if(FREEBSD)
  set(TABLE_PLATFORM "freebsd")

  include_directories("/usr/local/include/libxml2")

  ADD_OSQUERY_LINK_ADDITIONAL("procstat")
  ADD_OSQUERY_LINK_ADDITIONAL("util")
  ADD_OSQUERY_LINK_ADDITIONAL("kvm")
  ADD_OSQUERY_LINK_ADDITIONAL("elf")
endif()

# Windows specific and applicable tables.
if(WINDOWS)
  set(TABLE_PLATFORM "windows")

  # Additional Windows libraries
  ADD_OSQUERY_LINK_ADDITIONAL("crypt32.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("Wintrust.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("Advapi32.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("Iphlpapi.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("SetupAPI.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("Ws2_32.lib")
  ADD_OSQUERY_LINK_ADDITIONAL("version.lib")
endif()

# Linux specific and applicable tables.
if(LINUX)
  set(TABLE_PLATFORM "linux")

  ADD_OSQUERY_LINK_ADDITIONAL("libresolv.so")
  ADD_OSQUERY_LINK_ADDITIONAL("cryptsetup devmapper lvm2app lvm-internal daemonclient")
  ADD_OSQUERY_LINK_ADDITIONAL("gcrypt gpg-error")
  ADD_OSQUERY_LINK_ADDITIONAL("blkid")
  ADD_OSQUERY_LINK_ADDITIONAL("ip4tc")

  ADD_OSQUERY_LINK_ADDITIONAL("dpkg lzma bz2")
  ADD_OSQUERY_LINK_ADDITIONAL("rpm rpmio popt db")
endif()

if(POSIX)
  ADD_OSQUERY_LINK_ADDITIONAL("augeas fa xml2")
  ADD_OSQUERY_LINK_ADDITIONAL("fuzzy")
endif()

# For each general category, add the C++ files in the base.
foreach(CATEGORY ${TABLE_CATEGORIES})
  file(GLOB OSQUERY_${CATEGORY}_TABLES
    "${CATEGORY}/*.[cpm]*"
    "${CATEGORY}/${TABLE_PLATFORM}/*.[cpm]*"
  )
  if(OSQUERY_${CATEGORY}_TABLES)
    ADD_OSQUERY_LIBRARY_ADDITIONAL(
      osquery_${CATEGORY}_tables
      ${OSQUERY_${CATEGORY}_TABLES}
    )
  endif()

  # POSIX tables.
  if(POSIX)
    file(GLOB OSQUERY_${CATEGORY}_POSIX_TABLES "${CATEGORY}/posix/*.[cpm]*")
    if(OSQUERY_${CATEGORY}_POSIX_TABLES)
      ADD_OSQUERY_LIBRARY_ADDITIONAL(
        osquery_${CATEGORY}_posix_tables
        ${OSQUERY_${CATEGORY}_POSIX_TABLES}
      )
    endif()

    # Add posix table tests.
    file(GLOB POSIX_OSQUERY_${CATEGORY}_TABLES_TESTS
      "${CATEGORY}/posix/tests/*.[cpm]*"
    )
    ADD_OSQUERY_TABLE_TEST(${POSIX_OSQUERY_${CATEGORY}_TABLES_TESTS})
  endif()

  # Table implementations shared by FreeBSD and Linux
  if(FREEBSD OR LINUX)
    file(GLOB OSQUERY_${CATEGORY}_FREENUX_TABLES "${CATEGORY}/freenux/*.[cpm]*")
    if(OSQUERY_${CATEGORY}_FREENUX_TABLES)
      ADD_OSQUERY_LIBRARY_ADDITIONAL(
        osquery_${CATEGORY}_freenux_tables
        ${OSQUERY_${CATEGORY}_FREENUX_TABLES}
      )
    endif()
  endif()

  # Add the table tests.
  file(GLOB OSQUERY_${CATEGORY}_TABLES_TESTS
    "${CATEGORY}/tests/*.[cpm]*"
    "${CATEGORY}/${TABLE_PLATFORM}/tests/*.[cpm]*"
  )
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_${CATEGORY}_TABLES_TESTS})
endforeach()

ADD_OSQUERY_LIBRARY_CORE(osquery_tables_utility
  "${CMAKE_CURRENT_LIST_DIR}/utility/file.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/utility/osquery.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/utility/time.cpp"
)

if(NOT SKIP_AWS AND LINUX)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_cloud_tables
    "${CMAKE_CURRENT_LIST_DIR}/cloud/ec2_instance_metadata.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/cloud/ec2_instance_tags.cpp"
  )
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-ec2")
endif()

if(NOT SKIP_TSK AND POSIX)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sleuthkit_tables
    "${CMAKE_CURRENT_LIST_DIR}/sleuthkit/sleuthkit.cpp"
  )
  ADD_OSQUERY_LINK_ADDITIONAL("tsk")
endif()

if(NOT SKIP_YARA AND POSIX)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_yara_tables
    "${CMAKE_CURRENT_LIST_DIR}/yara/yara.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/yara/yara_events.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/yara/yara_utils.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/yara/yara_utils.h"
  )
  ADD_OSQUERY_TABLE_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/yara/tests/yara_tests.cpp"
  )
  ADD_OSQUERY_LINK_ADDITIONAL("yara")
endif()

if(NOT SKIP_LLDPD AND POSIX)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_lldpd_tables
    "${CMAKE_CURRENT_LIST_DIR}/lldpd/lldp_neighbors.cpp"
  )
  ADD_OSQUERY_LINK_ADDITIONAL("lldpctl")
endif()
