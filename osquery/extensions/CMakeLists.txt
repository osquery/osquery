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
set(OSQUERY_THRIFT_DIR "${OSQUERY_THRIFT_DIR}" PARENT_SCOPE)
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
  set(OSQUERY_THRIFT_DIR "${OSQUERY_THRIFT_DIR}" PARENT_SCOPE)
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

  ADD_OSQUERY_LINK_CORE("transport server concurrency security protocol async")
  # ADD_OSQUERY_LINK_CORE("follyinit follysymbolizer")
  ADD_OSQUERY_LINK_CORE("libfolly.so.57.0.0")
  ADD_OSQUERY_LINK_CORE("wangle")
  ADD_OSQUERY_LINK_CORE("mstch")
  ADD_OSQUERY_LINK_CORE("thriftcpp2 thrift-core thriftprotocol thriftfrozen2")
  ADD_OSQUERY_LINK_CORE("gssapi_krb5")
  ADD_OSQUERY_LINK_CORE("event")
  ADD_OSQUERY_LINK_CORE("libsnappy.so")
  ADD_OSQUERY_LINK_CORE("double-conversion")
endif()

find_program(THRIFT_COMPILER ${THRIFT_NAME} ${BUILD_DEPS} ENV PATH)

# Generate the thrift intermediate/interface code.
if(LINUX OR DARWIN)
  if(DEFINED ENV{FBTHRIFT})
    add_custom_command(
      COMMAND
        LD_LIBRARY_PATH=${BUILD_DEPS}/lib:$ENV{LD_LIBRARY_PATH}
        ${THRIFT_COMPILER} --gen mstch_cpp2:include_prefix=generated --gen py
        --templates "${BUILD_DEPS}/include/thrift/templates"
        -o "${CMAKE_BINARY_DIR}/generated"
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
      DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
      OUTPUT ${THRIFT_GENERATED_FILES}
    )
    add_definitions(-DFBTHRIFT -Wno-c++17-extensions)
  else()
    add_custom_command(
      COMMAND
        LD_LIBRARY_PATH=${BUILD_DEPS}/lib:$ENV{LD_LIBRARY_PATH}
        ${THRIFT_COMPILER} --gen cpp --gen py
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
      DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
      OUTPUT ${THRIFT_GENERATED_FILES}
    )
  endif()
else()
  add_custom_command(
    COMMAND
      ${THRIFT_COMPILER} --gen ${THRIFT_TYPE} --gen py
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
    DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
    OUTPUT ${THRIFT_GENERATED_FILES}
  )
endif()

if(NOT WINDOWS)
  add_compile_options(
    -Wno-macro-redefined
  )
endif()

# Set the include directory for generated Thrift files.
include_directories("${OSQUERY_THRIFT_DIR}")

ADD_OSQUERY_LIBRARY(TRUE osquery_extensions
  ${THRIFT_GENERATED_FILES}
  extensions.cpp
  interface.cpp
)

file(GLOB OSQUERY_EXTENSIONS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EXTENSIONS_TESTS})
