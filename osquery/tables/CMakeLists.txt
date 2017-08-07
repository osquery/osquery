#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

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
  ADD_OSQUERY_LINK_ADDITIONAL("cryptsetup devmapper")
  ADD_OSQUERY_LINK_ADDITIONAL("gcrypt gpg-error")
  ADD_OSQUERY_LINK_ADDITIONAL("blkid")
  ADD_OSQUERY_LINK_ADDITIONAL("ip4tc")

  ADD_OSQUERY_LINK_ADDITIONAL("apt-pkg dpkg lzma lz4 bz2")
  ADD_OSQUERY_LINK_ADDITIONAL("rpm rpmio beecrypt popt db")
endif()

if(POSIX)
  ADD_OSQUERY_LINK_ADDITIONAL("augeas fa xml2")
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

file(GLOB OSQUERY_UTILITY_TABLES "utility/*.cpp")
ADD_OSQUERY_LIBRARY_CORE(osquery_tables_utility
  ${OSQUERY_UTILITY_TABLES}
)

if(NOT SKIP_AWS AND LINUX)
  file(GLOB OSQUERY_CLOUD_TABLES "cloud/*.[cpm]*")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_cloud_tables ${OSQUERY_CLOUD_TABLES})
 
  file(GLOB OSQUERY_CLOUD_TABLES_TESTS "cloud/tests/*.[cpm]*")
  if(OSQUERY_CLOUD_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_CLOUD_TABLES_TESTS})
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-ec2")
endif()

if(NOT SKIP_TSK AND POSIX)
  file(GLOB OSQUERY_TSK_TABLES "sleuthkit/*.[cpm]*")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sleuthkit_tables ${OSQUERY_TSK_TABLES})

  file(GLOB OSQUERY_TSK_TABLES_TESTS "sleuthkit/tests/*.[cpm]*")
  if(OSQUERY_TSK_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_TSK_TABLES_TESTS})
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("tsk")
endif()

if(NOT SKIP_YARA AND POSIX)
  file(GLOB OSQUERY_YARA_TABLES "yara/*.[cpm]*")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_yara_tables ${OSQUERY_YARA_TABLES})

  file(GLOB OSQUERY_YARA_TABLES_TESTS "yara/tests/*.[cpm]*")
  if(OSQUERY_YARA_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_YARA_TABLES_TESTS})
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("yara")
endif()

if(NOT SKIP_LLDPD AND POSIX)
  file(GLOB OSQUERY_LLDPD_TABLES "lldpd/*.[cpm]*")
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_lldpd_tables ${OSQUERY_LLDPD_TABLES})

  file(GLOB OSQUERY_LLDPD_TABLES_TESTS "lldpd/tests/*.[cpm]*")
  if(OSQUERY_LLDPD_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_LLDPD_TABLES_TESTS})
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("lldpctl")
endif()
