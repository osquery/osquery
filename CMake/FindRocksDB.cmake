# -*- mode: cmake; -*-
# - Try to find rocksdb include dirs and libraries
# Usage of this module as follows:
# This file defines:
# * ROCKSDB_FOUND if protoc was found
# * ROCKSDB_LIBRARY The lib to link to (currently only a static unix lib, not
# portable)
# * ROCKSDB_INCLUDE The include directories for rocksdb.

include(FindPackageHandleStandardArgs)

# set defaults
SET(_rocksdb_HOME "/opt/rocksdb")
SET(_rocksdb_INCLUDE_SEARCH_DIRS
  ${CMAKE_INCLUDE_PATH}
  /usr/local/include
  /usr/include
  /opt/rocksdb/include
)

SET(_rocksdb_LIBRARIES_SEARCH_DIRS
  ${CMAKE_LIBRARY_PATH}
  /usr/local/lib
  /usr/lib
  /opt/rocksdb
)

##
if( "${ROCKSDB_HOME}" STREQUAL "")
  if("" MATCHES "$ENV{ROCKSDB_HOME}")
    set (ROCKSDB_HOME ${_rocksdb_HOME})
  else("" MATCHES "$ENV{ROCKSDB_HOME}")
    set (ROCKSDB_HOME "$ENV{ROCKSDB_HOME}")
  endif("" MATCHES "$ENV{ROCKSDB_HOME}")
else( "${ROCKSDB_HOME}" STREQUAL "")
  message(STATUS "ROCKSDB_HOME is not empty: \"${ROCKSDB_HOME}\"")
endif( "${ROCKSDB_HOME}" STREQUAL "")
##

IF( NOT ${ROCKSDB_HOME} STREQUAL "" )
  SET(_rocksdb_INCLUDE_SEARCH_DIRS ${ROCKSDB_HOME}/include ${_rocksdb_INCLUDE_SEARCH_DIRS})
  SET(_rocksdb_LIBRARIES_SEARCH_DIRS ${ROCKSDB_HOME}/lib ${_rocksdb_LIBRARIES_SEARCH_DIRS})
  SET(_rocksdb_HOME ${ROCKSDB_HOME})
ENDIF( NOT ${ROCKSDB_HOME} STREQUAL "" )

IF( NOT $ENV{ROCKSDB_INCLUDEDIR} STREQUAL "" )
  SET(_rocksdb_INCLUDE_SEARCH_DIRS $ENV{ROCKSDB_INCLUDEDIR} ${_rocksdb_INCLUDE_SEARCH_DIRS})
ENDIF( NOT $ENV{ROCKSDB_INCLUDEDIR} STREQUAL "" )

IF( NOT $ENV{ROCKSDB_LIBRARYDIR} STREQUAL "" )
  SET(_rocksdb_LIBRARIES_SEARCH_DIRS $ENV{ROCKSDB_LIBRARYDIR} ${_rocksdb_LIBRARIES_SEARCH_DIRS})
ENDIF( NOT $ENV{ROCKSDB_LIBRARYDIR} STREQUAL "" )

IF( ROCKSDB_HOME )
  SET(_rocksdb_INCLUDE_SEARCH_DIRS ${ROCKSDB_HOME}/include ${_rocksdb_INCLUDE_SEARCH_DIRS})
  SET(_rocksdb_LIBRARIES_SEARCH_DIRS ${ROCKSDB_HOME}/lib ${_rocksdb_LIBRARIES_SEARCH_DIRS})
  SET(_rocksdb_HOME ${ROCKSDB_HOME})
ENDIF( ROCKSDB_HOME )

# find the include files
FIND_PATH(ROCKSDB_INCLUDE_DIR rocksdb/db.h
  HINTS
  ${_rocksdb_INCLUDE_SEARCH_DIRS}
  ${PC_ROCKSDB_INCLUDEDIR}
  ${PC_ROCKSDB_INCLUDE_DIRS}
  ${CMAKE_INCLUDE_PATH}
)

# locate the library
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # On MacOS
  set(ROCKSDB_LIBRARY_NAMES librocksdb.dylib)
  set(ROCKSDB_LITE_LIBRARY_NAMES librocksdb_lite.dylib)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  # On Linux
  set(ROCKSDB_LIBRARY_NAMES librocksdb.so)
  set(ROCKSDB_LITE_LIBRARY_NAMES librocksdb_lite.so)
else()
  set(ROCKSDB_LIBRARY_NAMES librocksdb.a)
  set(ROCKSDB_LITE_LIBRARY_NAMES librocksdb_lite.a)
endif()

set(ROCKSDB_STATIC_LIBRARY_NAMES librocksdb.a)
set(ROCKSDB_LITE_STATIC_LIBRARY_NAMES librocksdb_lite.a)

find_library(ROCKSDB_LIBRARIES NAMES ${ROCKSDB_LIBRARY_NAMES}
  HINTS ${_rocksdb_LIBRARIES_SEARCH_DIRS}
)

find_library(ROCKSDB_LITE_LIBRARIES NAMES ${ROCKSDB_LITE_LIBRARY_NAMES}
  HINTS ${_rocksdb_LIBRARIES_SEARCH_DIRS}
)

find_library(ROCKSDB_STATIC_LIBRARY NAMES ${ROCKSDB_STATIC_LIBRARY_NAMES}
  HINTS ${_rocksdb_LIBRARIES_SEARCH_DIRS}
)

find_library(ROCKSDB_LITE_STATIC_LIBRARY NAMES ${ROCKSDB_LITE_STATIC_LIBRARY_NAMES}
  HINTS ${_rocksdb_LIBRARIES_SEARCH_DIRS}
)

find_library(ROCKSDB_SNAPPY_LIBRARY NAMES libsnappy.a
  HINTS ${_rocksdb_LIBRARIES_SEARCH_DIRS}
)

# If the lite library was found, override and prefer LITE.
if(NOT ${ROCKSDB_LITE_LIBRARIES} STREQUAL "ROCKSDB_LITE_LIBRARIES-NOTFOUND")
  set(ROCKSDB_LIBRARIES ${ROCKSDB_LITE_LIBRARIES})
  set(ROCKSDB_LITE_FOUND "YES")
endif()

if(NOT ${ROCKSDB_LITE_STATIC_LIBRARY} STREQUAL "ROCKSDB_LITE_STATIC_LIBRARY-NOTFOUND")
  set(ROCKSDB_STATIC_LIBRARY ${ROCKSDB_LITE_STATIC_LIBRARY})
  set(ROCKSDB_LITE_FOUND "YES")
endif()

# If shared libraries are not found, fall back to static.
# If not explicitly building using shared libraries, prefer static libraries.
if(${ROCKSDB_LIBRARIES} STREQUAL "ROCKSDB_LIBRARIES-NOTFOUND"
    OR NOT DEFINED $ENV{BUILD_LINK_SHARED})
  set(ROCKSDB_LIBRARIES ${ROCKSDB_STATIC_LIBRARY} ${ROCKSDB_SNAPPY_LIBRARY})
  LOG_LIBRARY(rocksdb "${ROCKSDB_STATIC_LIBRARY}")
  LOG_LIBRARY(snappy "${ROCKSDB_SNAPPY_LIBRARY}")
else()
  LOG_LIBRARY(rocksdb "${ROCKSDB_LIBRARIES}")
endif()

# if the include and the program are found then we have it
if(ROCKSDB_INCLUDE_DIR AND ROCKSDB_LIBRARIES)
  set(ROCKSDB_FOUND "YES")
endif()

# Check for RocksDB LITE by detecting missing symbols at link time.
# If the LITE version is installed, we must also define ROCKSDB_LITE=1.
include(CheckCXXSourceCompiles)
set(CMAKE_CXX_FLAGS ${CXX_COMPILE_FLAGS})
set(CMAKE_REQUIRED_LIBRARIES rocksdb snappy)
check_cxx_source_compiles("
  #include <rocksdb/db.h>
  using namespace rocksdb;
  // Check for symbol that does not exist with -DROCKSDB_LITE=1
  int main(int, char**) {
    Options options;
    auto status = RepairDB(\"test\", options);
    return 0;
  }" ROCKSDB_NON_LITE)

if(${ROCKSDB_NON_LITE})
  WARNING_LOG("RocksDB was NOT installed as RocksDB LITE [Reference #1259]")
  WARNING_LOG("Installing RocksDB with -DROCKSDB_LITE=1 will improve osquery performance")
else()
  add_definitions(-DROCKSDB_LITE=1)
endif()

