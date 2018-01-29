#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# For the extensions targets, allow them to include thrift interface headers.
# include_directories("${OSQUERY_THRIFT_DIR}")

set(THRIFT_NAME "thrift")
set(OSQUERY_THRIFT_DIR "${CMAKE_BINARY_DIR}/generated/gen-cpp")
set(THRIFT_GENERATED_FILES
  ${OSQUERY_THRIFT_DIR}/Extension.cpp
  ${OSQUERY_THRIFT_DIR}/Extension.h
  ${OSQUERY_THRIFT_DIR}/ExtensionManager.cpp
  ${OSQUERY_THRIFT_DIR}/ExtensionManager.h
  ${OSQUERY_THRIFT_DIR}/osquery_types.cpp
  ${OSQUERY_THRIFT_DIR}/osquery_types.h
)

if(DEFINED ENV{FBTHRIFT})
  set(THRIFT_NAME "thrift1")
  set(OSQUERY_THRIFT_DIR "${CMAKE_BINARY_DIR}/generated/gen-cpp2")
  set(THRIFT_GENERATED_FILES
    ${OSQUERY_THRIFT_DIR}/Extension_client.cpp
    ${OSQUERY_THRIFT_DIR}/Extension.cpp
    ${OSQUERY_THRIFT_DIR}/ExtensionManager_client.cpp
    ${OSQUERY_THRIFT_DIR}/ExtensionManager.cpp
    ${OSQUERY_THRIFT_DIR}/ExtensionManager_processmap_binary.cpp
    ${OSQUERY_THRIFT_DIR}/ExtensionManager_processmap_compact.cpp
    ${OSQUERY_THRIFT_DIR}/Extension_processmap_binary.cpp
    ${OSQUERY_THRIFT_DIR}/Extension_processmap_compact.cpp
    ${OSQUERY_THRIFT_DIR}/osquery_constants.cpp
    ${OSQUERY_THRIFT_DIR}/osquery_data.cpp
    ${OSQUERY_THRIFT_DIR}/osquery_types.cpp
  )
  include_directories("${CMAKE_BINARY_DIR}")
  add_definitions(-DFBTHRIFT=1)
endif()

find_program(THRIFT_COMPILER ${THRIFT_NAME} ${BUILD_DEPS} ENV PATH)

# Set the include directory for generated Thrift files.
include_directories("${OSQUERY_THRIFT_DIR}")
