SET(OSQUERY_LIBS
  readline
  pthread
)

SET(OSQUERY_APPLE_LIBS
  /usr/local/lib/libboost_thread-mt.a
  /usr/local/lib/libboost_system.a
  /usr/local/lib/libboost_filesystem.a
  /usr/local/lib/libboost_program_options.a
  /usr/local/lib/libboost_regex.a
  /usr/local/lib/libthrift.a
  /usr/local/lib/librocksdb.a
  /usr/local/lib/libsnappy.a
  /usr/local/lib/liblz4.a
  /usr/local/lib/libgflags.a
  /usr/local/lib/libglog.a
  /usr/local/opt/openssl/lib/libcrypto.a
  /usr/local/opt/openssl/lib/libssl.a
  dl
  bz2
  z
)

# Warning: Do not statically compile unwind
SET(OSQUERY_LINUX_LIBS
  libgflags.a
  libglog.a
  librocksdb.a
  libthrift.a
  libboost_thread.a
  libboost_system.a
  libboost_filesystem.a
  libboost_program_options.a
  libboost_regex.a

  bz2
  crypto
  dl
  rt
  ssl
  unwind
  z
)

SET(OSQUERY_UBUNTU_LIBS
  libsnappy.a
  liblzma.a
)

SET(OSQUERY_CENTOS_LIBS
  libsnappy.so
  liblzma.so
)

SET(OSQUERY_FREEBSD_LIBS
  gflags
  glog
  rocksdb
  thrift
  boost_thread
  boost_system
  boost_filesystem
  boost_program_options
  boost_regex

  bz2
  crypto
  lzma
  rt
  snappy
  ssl
  unwind
  z
)

# Check for the explicit path to determine the version of procps
if(EXISTS "/usr/lib/libprocps.a"
    OR EXISTS "/usr/lib/x86_64-linux-gnu/libprocps.a")
  set(PROCPS True)
else()
  set(PROCPS False)
endif()

# Fill this in with objects for libosquery
set(OSQUERY_SOURCES "")
# Fill this in with links and linker options for libosquery
set(OSQUERY_LINKS "")
# Fill this in in with non-core links and linker options (for tables)
set(OSQUERY_ADDITIONAL_SOURCES "")
set(OSQUERY_ADDITIONAL_LINKS "")

set(Boost_USE_STATIC_LIBS ON)
if(NOT BUILD_SHARED)
  SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
  SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
endif()

# Generate version from git
execute_process(
  COMMAND git describe --tags HEAD --always
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_BUILD_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

ADD_DEFINITIONS("
-DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}
-D${OSQUERY_BUILD_OS}
-D${OSQUERY_BUILD_OS}_${OSQUERY_BUILD_DISTRO}
")

# Core/non core link helping macros (tell the build to link ALL).
MACRO(ADD_OSQUERY_LINK LINK)
  list(APPEND OSQUERY_LINKS ${LINK})
  set(OSQUERY_ADDITIONAL_LINKS ${OSQUERY_ADDITIONAL_LINKS} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_LINK)
MACRO(ADD_OSQUERY_CORE_LINK LINK)
  list(APPEND OSQUERY_LINKS ${LINK})
  set(OSQUERY_LINKS ${OSQUERY_LINKS} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_CORE_LINK)

# Core/non core lists of target source files.
MACRO(ADD_OSQUERY_LIBRARY TARGET)
  ADD_LIBRARY(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_LIBRARY TARGET)
MACRO(ADD_OSQUERY_CORE_LIBRARY TARGET)
  ADD_LIBRARY(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_CORE_LIBRARY TARGET)

# Core/non core lists of target source files compiled as ObjC++.
MACRO(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)
  ADD_LIBRARY(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)
MACRO(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)
  ADD_LIBRARY(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
ENDMACRO(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)

# Helper to abstract OS/Compiler whole linking.
MACRO(TARGET_OSQUERY_LINK_WHOLE TARGET OSQUERY_LIB)
  TARGET_LINK_LIBRARIES(${TARGET} "${OS_WHOLELINK_PRE}")
  TARGET_LINK_LIBRARIES(${TARGET} ${OSQUERY_LIB})
  TARGET_LINK_LIBRARIES(${TARGET} "${OS_WHOLELINK_POST}")
ENDMACRO(TARGET_OSQUERY_LINK_WHOLE)

# Fill in libraries for Apple, Uunbut, Centos, FreeBSD
if(APPLE)
  set(OSQUERY_LIBS ${OSQUERY_LIBS} ${OSQUERY_APPLE_LIBS})
  ADD_OSQUERY_LINK("-mmacosx-version-min=${APPLE_MIN_ABI}")
elseif(FREEBSD)
  set(OSQUERY_LIBS ${OSQUERY_LIBS} ${OSQUERY_FREEBSD_LIBS})
else()
  set(OSQUERY_LIBS ${OSQUERY_LIBS} ${OSQUERY_LINUX_LIBS})
  if(UBUNTU)
    set(OSQUERY_LIBS ${OSQUERY_LIBS} ${OSQUERY_UBUNTU_LIBS})
  elseif(CENTOS)
    set(OSQUERY_LIBS ${OSQUERY_LIBS} ${OSQUERY_CENTOS_LIBS})
  endif()
endif()

# Make sure deps were built before compiling
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" check "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_DEPS_MESSAGE
  RESULT_VARIABLE OSQUERY_DEPS_CHECK
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Add subdirectories
ADD_SUBDIRECTORY(config)
ADD_SUBDIRECTORY(core)
ADD_SUBDIRECTORY(database)
ADD_SUBDIRECTORY(devtools)
ADD_SUBDIRECTORY(dispatcher)
ADD_SUBDIRECTORY(events)
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(filesystem)
ADD_SUBDIRECTORY(logger)
ADD_SUBDIRECTORY(scheduler)

SET(OSQUERY_LIB_OBJECTS
  # Third-party objects
  $<TARGET_OBJECTS:osquery_sqlite>
  # Build additional os-dependent libraries (may include tables)
  ${OSQUERY_SOURCES}
)

# If the builder wants to include the additional.
#ADD_SUBDIRECTORY(tables)
#include(tables/CMakeLibs.txt)
#SET(OSQUERY_GENERATED_OBJECTS "")
#GENERATE_TABLES("${CMAKE_SOURCE_DIR/tables" OSQUERY_GENERATED_OBJECTS)
#SET(OSQUERY_LIB_OBJECTS ${OSQUERY_LIB_OBJECTS} ${OSQUERY_ADDITIONAL_SOURCES})
#SET(OSQUERY_LIB_OBJECTS ${OSQUERY_LIB_OBJECTS} ${OSQUERY_GENERATED_OBJECTS})
#SET(OSQUERY_LINKS ${OSQUERY_LINKS} ${OSQUERY_ADDITIONAL_LINK})

# Create the static libosquery
set(CMAKE_MACOSX_RPATH 0)
ADD_LIBRARY(libosquery STATIC main/lib.cpp ${OSQUERY_LIB_OBJECTS}) # ${OSQUERY_CORE_TABLE_OBJECTS}
TARGET_LINK_LIBRARIES(libosquery ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(libosquery PROPERTIES OUTPUT_NAME osquery)
INSTALL(TARGETS libosquery DESTINATION lib)

# Include the public API includes
INSTALL(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION include)

ADD_EXECUTABLE(shell main/shell.cpp)
TARGET_LINK_LIBRARIES(shell libosquery)
SET_TARGET_PROPERTIES(shell PROPERTIES OUTPUT_NAME osqueryi)
SET_TARGET_PROPERTIES(shell PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
INSTALL(TARGETS shell DESTINATION bin)

ADD_EXECUTABLE(daemon main/daemon.cpp)
TARGET_LINK_LIBRARIES(daemon libosquery)
SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME osqueryd)
SET_TARGET_PROPERTIES(daemon PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
INSTALL(TARGETS daemon DESTINATION bin)

# packages

if(LINUX)
  SET(CPACK_PACKAGE_NAME "osquery")
  SET(CPACK_PACKAGE_VENDOR "facebook")

  SET(CPACK_PACKAGE_VERSION "${OSQUERY_BUILD_VERSION}")

  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
  SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "osquery is an operating system instrumentation toolchain.")

  EXECUTE_PROCESS(COMMAND uname -m OUTPUT_VARIABLE OSQUERY_ARCH)
  STRING(REPLACE "\n" "" OSQUERY_ARCH ${OSQUERY_ARCH})

  if(UBUNTU)
    SET(CPACK_GENERATOR "DEB")

    EXECUTE_PROCESS(COMMAND grep DISTRIB_CODENAME /etc/lsb-release OUTPUT_VARIABLE DISTRO)
    STRING(REPLACE "DISTRIB_CODENAME=" "" DISTRO ${DISTRO})
    STRING(REPLACE "\n" "" DISTRO ${DISTRO})

    EXECUTE_PROCESS(COMMAND dpkg --print-architecture OUTPUT_VARIABLE DPKG_ARCH)
    STRING(REPLACE "\n" "" DPKG_ARCH ${DPKG_ARCH})

    SET(CPACK_SYSTEM_NAME "${DISTRO}.${DPKG_ARCH}")
    SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${DPKG_ARCH})
    SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "marpaia@fb.com")
  endif()

  INCLUDE(CPack)
endif()
