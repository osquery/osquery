# Generate the thrift intermediate/interface code.
add_custom_command(
  COMMAND
    ${THRIFT_COMPILER} --gen cpp --gen py "${CMAKE_SOURCE_DIR}/osquery.thrift"
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
