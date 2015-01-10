# Fill this in with objects and (linker/linker options) for libosquery.
set(OSQUERY_SOURCES "")
set(OSQUERY_LINKS "")
# Fill this in in with non-core links and linker options (for plugins).
set(OSQUERY_ADDITIONAL_SOURCES "")
set(OSQUERY_ADDITIONAL_LINKS "")

set(Boost_USE_STATIC_LIBS ON)
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# The core set of osquery libraries most discovered with find_package.
set(OSQUERY_LIBS
  ${THRIFT_LIB}
  ${ROCKSDB_STATIC_LIBRARIES}
  ${ROCKSDB_SNAPPY_LIBRARY}
  ${GLOG_LIBRARY}
  ${GFLAGS_LIBRARY}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_SSL_LIBRARY}

  readline
  pthread
  dl
  bz2
  z
)

# The platform-specific core libraries.
if(APPLE)
  ADD_OSQUERY_CORE_LINK("-mmacosx-version-min=${APPLE_MIN_ABI}")
  ADD_OSQUERY_CORE_LINK("boost_thread-mt")
  ADD_OSQUERY_CORE_LINK("lz4")
else()
  # Warning: Do not statically compile unwind, also requires LZMA
  list(APPEND OSQUERY_LIBS "${LZMA_LIBRARY}" "unwind")
  ADD_OSQUERY_CORE_LINK("boost_thread")
endif()

# The remaining boost libraries are discovered with find_library.
ADD_OSQUERY_CORE_LINK("boost_system")
ADD_OSQUERY_CORE_LINK("boost_filesystem")
ADD_OSQUERY_CORE_LINK("boost_program_options")
ADD_OSQUERY_CORE_LINK("boost_regex")

# Generate version from git
execute_process(
  COMMAND git describe --tags HEAD --always
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_BUILD_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_definitions("
-DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}
-D${OSQUERY_BUILD_OS}
-D${OSQUERY_BUILD_OS}_${OSQUERY_BUILD_DISTRO}
")

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
set(OSQUERY_OBJECTS $<TARGET_OBJECTS:osquery_sqlite>)

# Add subdirectories
add_subdirectory(config)
add_subdirectory(core)
add_subdirectory(database)
add_subdirectory(devtools)
add_subdirectory(dispatcher)
add_subdirectory(events)
add_subdirectory(examples)
add_subdirectory(filesystem)
add_subdirectory(logger)
add_subdirectory(scheduler)
add_subdirectory(tables)

# Utility tables are table specs that are ALWAYS built into osquery core.
GENERATE_UTILITY("osquery_info")
GENERATE_UTILITY("osquery_flags")
GENERATE_UTILITY("time")
GENERATE_UTILITY("file")
GENERATE_UTILITY("hash")

# Finally amalgamate all the tables.
AMALGAMATE("${CMAKE_SOURCE_DIR}" "utils" AMALGAMATION_UTILS)
ADD_OSQUERY_CORE_LIBRARY(osquery_utils_amalgamation ${AMALGAMATION_UTILS})

list(APPEND OSQUERY_OBJECTS ${OSQUERY_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_LINKS})

# Create the static libosquery.
set(CMAKE_MACOSX_RPATH 0)
add_library(libosquery_basic STATIC main/lib.cpp ${OSQUERY_OBJECTS})
target_link_libraries(libosquery_basic ${OSQUERY_LIBS})
set_target_properties(libosquery_basic PROPERTIES OUTPUT_NAME osquery_basic)
install(TARGETS libosquery_basic DESTINATION lib)

# Generate the osquery core tables (the non-util).
GENERATE_TABLES("${CMAKE_SOURCE_DIR}/osquery/tables" "${CMAKE_SOURCE_DIR}")
AMALGAMATE("${CMAKE_SOURCE_DIR}" "additional" AMALGAMATION)
ADD_OSQUERY_LIBRARY(osquery_amalgamation ${AMALGAMATION})

# Create the static libosquery_additional.
add_library(libosquery_additional STATIC ${OSQUERY_ADDITIONAL_SOURCES})
target_link_libraries(libosquery_additional ${OSQUERY_ADDITIONAL_LINKS})
set_target_properties(libosquery_additional PROPERTIES OUTPUT_NAME osquery_additional)
install(TARGETS libosquery_additional DESTINATION lib)

# Optionally build a shared library.
add_library(libosquery SHARED EXCLUDE_FROM_ALL main/empty.cpp)
TARGET_OSQUERY_LINK_WHOLE(libosquery libosquery_basic)
TARGET_OSQUERY_LINK_WHOLE(libosquery libosquery_additional)
set_target_properties(libosquery PROPERTIES OUTPUT_NAME osquery)

# Include the public API includes.
install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION include)

add_executable(shell main/shell.cpp)
TARGET_OSQUERY_LINK_WHOLE(shell libosquery_basic)
TARGET_OSQUERY_LINK_WHOLE(shell libosquery_additional)
set_target_properties(shell PROPERTIES OUTPUT_NAME osqueryi)
set_target_properties(shell PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
install(TARGETS shell DESTINATION bin)

add_executable(daemon main/daemon.cpp)
TARGET_OSQUERY_LINK_WHOLE(daemon libosquery_basic)
TARGET_OSQUERY_LINK_WHOLE(daemon libosquery_additional)
set_target_properties(daemon PROPERTIES OUTPUT_NAME osqueryd)
set_target_properties(daemon PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
install(TARGETS daemon DESTINATION bin)

add_executable(run main/run.cpp)
TARGET_OSQUERY_LINK_WHOLE(run libosquery_basic)
TARGET_OSQUERY_LINK_WHOLE(run libosquery_additional)
set_target_properties(run PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
install(TARGETS run DESTINATION bin)

add_executable(osqueryctl main/ctl.cpp)
TARGET_OSQUERY_LINK_WHOLE(osqueryctl libosquery_basic)
TARGET_OSQUERY_LINK_WHOLE(osqueryctl libosquery_additional)
set_target_properties(osqueryctl PROPERTIES OUTPUT_NAME osqueryctl)
set_target_properties(osqueryctl PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
install(TARGETS osqueryctl DESTINATION bin)

# packages
if(LINUX)
  set(CPACK_PACKAGE_NAME "osquery")
  set(CPACK_PACKAGE_VENDOR "facebook")
  set(CPACK_PACKAGE_VERSION "${OSQUERY_BUILD_VERSION}")
  set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "osquery is an operating system instrumentation toolchain.")

  execute_process(COMMAND uname -m OUTPUT_VARIABLE OSQUERY_ARCH)
  string(REPLACE "\n" "" OSQUERY_ARCH ${OSQUERY_ARCH})

  if(UBUNTU)
    set(CPACK_GENERATOR "DEB")

    execute_process(COMMAND dpkg --print-architecture OUTPUT_VARIABLE DPKG_ARCH)
    string(REPLACE "\n" "" DPKG_ARCH ${DPKG_ARCH})

    set(CPACK_SYSTEM_NAME "${OSQUERY_BUILD_DISTRO}.${DPKG_ARCH}")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${DPKG_ARCH})
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "marpaia@fb.com")
  endif()

  include(CPack)
endif()
