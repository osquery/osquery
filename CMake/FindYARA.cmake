include(FindPackageHandleStandardArgs)
if(POLICY CMP0054)
  cmake_policy(SET CMP0054 NEW)
endif()

set(YARA_VERSION "3.3.0")

set(YARA_ROOT_DIR "${CMAKE_BINARY_DIR}/third-party/yara-${YARA_VERSION}")
set(YARA_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/yara-${YARA_VERSION}")

set(YARA_PATCH_01 "${CMAKE_SOURCE_DIR}/third-party/yara-${YARA_VERSION}/fc4696c8b725be1ac099d340359c8d550d116041.diff")

INCLUDE(ExternalProject)
ExternalProject_Add(
  yara
  SOURCE_DIR ${YARA_SOURCE_DIR}
  INSTALL_DIR ${YARA_ROOT_DIR}
  PATCH_COMMAND patch -p1 < ${YARA_PATCH_01}
  CONFIGURE_COMMAND ${YARA_SOURCE_DIR}/configure
    CC=/usr/bin/clang CXX=/usr/bin/clang++ --prefix=${YARA_ROOT_DIR}
  BUILD_COMMAND make
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND make install
  LOG_CONFIGURE ON
  LOG_INSTALL ON
  LOG_BUILD ON
)

ExternalProject_Add_Step(
  yara bootstrap
  COMMAND sh ./bootstrap.sh
  DEPENDERS configure
  WORKING_DIRECTORY ${YARA_SOURCE_DIR}
)

set(YARA_INCLUDE_DIR "${YARA_ROOT_DIR}/include")
set(YARA_INCLUDE_DIRS ${YARA_INCLUDE_DIR})

set(YARA_LIBRARY "${YARA_ROOT_DIR}/lib/libyara.a")
set(YARA_LIBRARIES ${YARA_LIBRARY})
