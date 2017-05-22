# Generate the thrift intermediate/interface code.
set(THRIFT_COMPILE_COMMAND "")
if(LINUX OR DARWIN)
  list(APPEND THRIFT_COMPILE_COMMAND
    "LD_LIBRARY_PATH=${BUILD_DEPS}/lib:$ENV{LD_LIBRARY_PATH}"
  )
endif()

list(APPEND THRIFT_COMPILE_COMMAND
  ${THRIFT_COMPILER}
  --gen cpp
  --gen py
  "${CMAKE_SOURCE_DIR}/osquery.thrift"
)

add_custom_command(
  COMMAND ${THRIFT_COMPILE_COMMAND}
  DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
  OUTPUT ${OSQUERY_THRIFT_GENERATED_FILES}
)

if(NOT WINDOWS)
  add_compile_options(
    -Wno-macro-redefined
  )
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_extensions
  ${OSQUERY_THRIFT_GENERATED_FILES}
  extensions.cpp
  interface.cpp
)

file(GLOB OSQUERY_EXTENSIONS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EXTENSIONS_TESTS})
