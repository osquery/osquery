#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

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

    ADD_OSQUERY_LINK_CORE("libfolly.so")
    ADD_OSQUERY_LINK_CORE("libsnappy.so")
    ADD_OSQUERY_LINK_CORE("wangle")
    ADD_OSQUERY_LINK_CORE("mstch")
    ADD_OSQUERY_LINK_CORE("gssapi_krb5")
    ADD_OSQUERY_LINK_CORE("event")
    ADD_OSQUERY_LINK_CORE("double-conversion")

    # FBThrift static libraries.
    ADD_OSQUERY_LINK_CORE("thriftcpp2 thrift-core thriftprotocol thriftfrozen2")
    ADD_OSQUERY_LINK_CORE("transport server concurrency security protocol async")
    ADD_OSQUERY_LINK_CORE("crypto ssl")
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

ADD_OSQUERY_LIBRARY(TRUE osquery_extensions
  ${THRIFT_GENERATED_FILES}
  extensions.cpp
  interface.cpp
)

file(GLOB OSQUERY_EXTENSIONS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EXTENSIONS_TESTS})
