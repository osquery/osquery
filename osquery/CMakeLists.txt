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
macro(ADD_OSQUERY_LINK LINK)
  list(APPEND OSQUERY_ADDITIONAL_LINKS ${LINK})
  set(OSQUERY_ADDITIONAL_LINKS ${OSQUERY_ADDITIONAL_LINKS} PARENT_SCOPE)
endmacro(ADD_OSQUERY_LINK)

macro(ADD_OSQUERY_CORE_LINK LINK)
  list(APPEND OSQUERY_LINKS ${LINK})
  set(OSQUERY_LINKS ${OSQUERY_LINKS} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_LINK)

# Core/non core lists of target source files.
macro(ADD_OSQUERY_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_ADDITIONAL_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_LIBRARY TARGET)

macro(ADD_OSQUERY_CORE_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_LIBRARY TARGET)

# Core/non core lists of target source files compiled as ObjC++.
macro(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)

macro(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)

# Helper to abstract OS/Compiler whole linking.
macro(TARGET_OSQUERY_LINK_WHOLE TARGET OSQUERY_LIB)
  TARGET_LINK_LIBRARIES(${TARGET} "${OS_WHOLELINK_PRE}")
  TARGET_LINK_LIBRARIES(${TARGET} ${OSQUERY_LIB})
  TARGET_LINK_LIBRARIES(${TARGET} "${OS_WHOLELINK_POST}")
endmacro(TARGET_OSQUERY_LINK_WHOLE)

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

# Construct a set of all object files, starting with third-party and all
# of the osquery core objects (sources from ADD_CORE_LIBRARY macros).
SET(OSQUERY_OBJECTS $<TARGET_OBJECTS:osquery_sqlite>)

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

# Include the tables and build the utilities tables.
include(tables/CMakeLibs.txt)
ADD_SUBDIRECTORY(tables)

# If the builder wants to include the additional non-utility core tables.
GENERATE_TABLES("${CMAKE_SOURCE_DIR}/osquery/tables" "${CMAKE_SOURCE_DIR}")
list(APPEND OSQUERY_OBJECTS ${OSQUERY_ADDITIONAL_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_ADDITIONAL_LINKS})

# Utility tables are table specs that are ALWAYS built into osquery core.
GENERATE_UTILITY("osquery_info")
GENERATE_UTILITY("osquery_flags")
GENERATE_UTILITY("time")
GENERATE_UTILITY("file")
GENERATE_UTILITY("hash")

# Finally amalgamate all the tables.
AMALGAMATE("${CMAKE_SOURCE_DIR}" AMALGAMATION_CORE)
ADD_OSQUERY_CORE_LIBRARY(osquery_core_tables ${AMALGAMATION_CORE})

list(APPEND OSQUERY_OBJECTS ${OSQUERY_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_LINKS})

# Create the static libosquery
set(CMAKE_MACOSX_RPATH 0)
ADD_LIBRARY(libosquery STATIC main/lib.cpp ${OSQUERY_OBJECTS})
TARGET_LINK_LIBRARIES(libosquery ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(libosquery PROPERTIES OUTPUT_NAME osquery)
INSTALL(TARGETS libosquery DESTINATION lib)

# Include the public API includes
INSTALL(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION include)

ADD_EXECUTABLE(shell main/shell.cpp)
TARGET_OSQUERY_LINK_WHOLE(shell libosquery)
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
