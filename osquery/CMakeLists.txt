#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# The 'core' source files define the osquery SDK (libosquery).
# There are macros throughout CMake to append sources to this list.
set(OSQUERY_SOURCES "")

# A separate list of library links (and linking options) is maintained for
# the 'core' set of sources.
set(OSQUERY_LINKS "")

# Finally a set of 'core' tests and kernel-tests, and benchmark tests, is kept.
set(OSQUERY_TESTS "")
set(OSQUERY_KERNEL_TESTS "")
set(OSQUERY_BENCHMARKS "")
set(OSQUERY_KERNEL_BENCHMARKS "")

# The 'additional' source files are NOT included with SDK (libosquery_additional).
set(OSQUERY_ADDITIONAL_SOURCES "")
set(OSQUERY_ADDITIONAL_LINKS "")
set(OSQUERY_ADDITIONAL_TESTS "")
set(OSQUERY_TABLES_TESTS "")

# Add all and extra for osquery code.
if(POSIX)
  add_compile_options(
    -Wall
    -Wextra
    -pedantic
    -Wuseless-cast
    -Wno-c99-extensions
    -Wno-zero-length-array
    -Wno-unused-parameter
    -Wno-gnu-case-range
  )
  if(NOT FREEBSD)
    add_compile_options(
      -Wshadow
    )
  endif()
endif()

if(DEFINED ENV{SANITIZE})
  if(DEFINED ENV{SANITIZE_THREAD})
    ADD_OSQUERY_LINK_CORE(-fsanitize=thread)
  elseif(DEFINED ENV{SANITIZE_UNDEFINED})
    ADD_OSQUERY_LINK_CORE(-fsanitize=undefined)
  else()
    ADD_OSQUERY_LINK_CORE(-fsanitize=address -fsanitize=leak)
  endif()
  ADD_OSQUERY_LINK_CORE(-fsanitize-blacklist=${SANITIZE_BLACKLIST})
endif()

# Construct a set of all object files, starting with third-party and all
# of the osquery core objects (sources from ADD_CORE_LIBRARY macros).
set(OSQUERY_OBJECTS $<TARGET_OBJECTS:osquery_sqlite>)

# Add subdirectories
add_subdirectory(config)
add_subdirectory(core)
add_subdirectory(database)
add_subdirectory(devtools)
add_subdirectory(dispatcher)
add_subdirectory(distributed)
add_subdirectory(events)
add_subdirectory(extensions)
add_subdirectory(filesystem)
add_subdirectory(logger)
add_subdirectory(registry)
add_subdirectory(sql)
add_subdirectory(remote)
add_subdirectory(utils)
if(NOT SKIP_CARVER)
  add_subdirectory(carver)
endif()

# Add externals directory from parent
add_subdirectory("${CMAKE_SOURCE_DIR}/external" "${CMAKE_BINARY_DIR}/external")

if(NOT SKIP_TABLES)
  add_subdirectory(tables)

  # Amalgamate the utility tables needed to compile.
  GENERATE_UTILITIES("${CMAKE_SOURCE_DIR}")
  AMALGAMATE("${CMAKE_SOURCE_DIR}" "utils" AMALGAMATION_UTILS)
  ADD_OSQUERY_LIBRARY_CORE(osquery_amalgamation ${AMALGAMATION_UTILS})
endif()

if(WINDOWS)
  if(DEFINED ENV{DEBUG})
    set(WB_KEY "sgd")
    set(WO_KEY "_dbg")
    set(WT_KEY "d_dbg")
  else()
    set(WB_KEY "s")
    set(WO_KEY "")
  endif()
  ADD_OSQUERY_LINK_CORE("ws2_32.lib")
  ADD_OSQUERY_LINK_CORE("iphlpapi.lib")
  ADD_OSQUERY_LINK_CORE("netapi32.lib")
  ADD_OSQUERY_LINK_CORE("rpcrt4.lib")
  ADD_OSQUERY_LINK_CORE("shlwapi.lib")
  ADD_OSQUERY_LINK_CORE("version.lib")
  ADD_OSQUERY_LINK_CORE("Wtsapi32.lib")
  ADD_OSQUERY_LINK_CORE("wbemuuid.lib")
  ADD_OSQUERY_LINK_CORE("taskschd.lib")
  ADD_OSQUERY_LINK_CORE("libboost_system-mt-${WB_KEY}")
  ADD_OSQUERY_LINK_CORE("libboost_regex-mt-${WB_KEY}")
  ADD_OSQUERY_LINK_CORE("libboost_filesystem-mt-${WB_KEY}")
  ADD_OSQUERY_LINK_CORE("libboost_context-mt-${WB_KEY}")
  ADD_OSQUERY_LINK_CORE("rocksdblib${WO_KEY}")
  ADD_OSQUERY_LINK_CORE("thriftmt${WT_KEY}")
  ADD_OSQUERY_LINK_CORE("linenoise${WO_KEY}.lib")
  ADD_OSQUERY_LINK_CORE("gflags_static${WO_KEY}")
  ADD_OSQUERY_LINK_CORE("ssleay32")
  ADD_OSQUERY_LINK_CORE("eay32")
  ADD_OSQUERY_LINK_CORE("zlibstatic")

  # Enable control flow guard
  ADD_OSQUERY_LINK_CORE("-guard:cf")
else()
  ADD_OSQUERY_LINK_CORE("libpthread")
  ADD_OSQUERY_LINK_CORE("libz")
  ADD_OSQUERY_LINK_CORE("gflags")
  ADD_OSQUERY_LINK_CORE("thrift")
endif()

if(APPLE OR LINUX)
  ADD_OSQUERY_LINK_CORE("libdl")
  ADD_OSQUERY_LINK_ADDITIONAL("rocksdb_lite")
elseif(FREEBSD)
  ADD_OSQUERY_LINK_CORE("icuuc")
  ADD_OSQUERY_LINK_ADDITIONAL("rocksdb-lite")
endif()

if(POSIX)
  ADD_OSQUERY_LINK_CORE("boost_system")
  ADD_OSQUERY_LINK_CORE("boost_filesystem")
  ADD_OSQUERY_LINK_CORE("boost_thread")
  ADD_OSQUERY_LINK_CORE("boost_context")
  ADD_OSQUERY_LINK_ADDITIONAL("boost_regex")
endif()

if(LINUX OR FREEBSD)
  ADD_OSQUERY_LINK_CORE("librt")
  ADD_OSQUERY_LINK_CORE("libc")
endif()

# Remaining additional development libraries.
ADD_OSQUERY_LINK_ADDITIONAL("cppnetlib-uri${WO_KEY}")
ADD_OSQUERY_LINK_ADDITIONAL("cppnetlib-client-connections${WO_KEY}")
ADD_OSQUERY_LINK_CORE("glog${WO_KEY}")

if(POSIX)
  ADD_OSQUERY_LINK_ADDITIONAL("ssl")
  ADD_OSQUERY_LINK_ADDITIONAL("crypto")
  ADD_OSQUERY_LINK_ADDITIONAL("libpthread")
  ADD_OSQUERY_LINK_ADDITIONAL("linenoise")
  ADD_OSQUERY_LINK_ADDITIONAL("magic")
endif()

if(APPLE)
  ADD_OSQUERY_LINK_CORE("liblzma libbz2")
else()
  if(POSIX)
    ADD_OSQUERY_LINK_CORE("lzma")
  endif()
  ADD_OSQUERY_LINK_CORE("bz2")
  ADD_OSQUERY_LINK_ADDITIONAL("bz2")
endif()

# The platform-specific SDK + core linker flags.
if(POSIX)
  ADD_OSQUERY_LINK_CORE("-rdynamic")
endif()

if(APPLE)
  ADD_OSQUERY_LINK_CORE("-Wl,-dead_strip")
  ADD_OSQUERY_LINK_CORE("-mmacosx-version-min=${OSX_VERSION_MIN}")
  ADD_OSQUERY_LINK_CORE("-Wl,-cache_path_lto,${CMAKE_BINARY_DIR}/ltocache")
elseif(LINUX OR FREEBSD)
  ADD_OSQUERY_LINK_CORE("-Wl,-zrelro -Wl,-znow")
  if(NOT DEFINED ENV{SANITIZE} AND NOT DEFINED ENV{DEBUG})
    ADD_OSQUERY_LINK_CORE("-pie")
  endif()
endif()

if(LINUX)
  ADD_OSQUERY_LINK_CORE("libgcc_s")
  ADD_OSQUERY_LINK_ADDITIONAL("uuid")
  if(DEFINED ENV{OSQUERY_BUILD_SHARED})
    ADD_OSQUERY_LINK_ADDITIONAL("-L${BUILD_DEPS}/legacy/lib")
  endif()
  if(NOT DEFINED ENV{OSQUERY_BUILD_LINK_SHARED})
    ADD_OSQUERY_LINK_CORE("-static-libstdc++")
    ADD_OSQUERY_LINK_ADDITIONAL("-static-libstdc++")
  endif()
  # For Ubuntu/CentOS packages add the build SHA1.
  ADD_OSQUERY_LINK_CORE("-Wl,--build-id")
  if (CMAKE_CXX_COMPILER MATCHES "clang")
    ADD_OSQUERY_LINK_CORE("-fuse-ld=lld")
  endif()
endif()

# Bubble the subdirectory (component) sources and links for this build.
list(APPEND OSQUERY_OBJECTS ${OSQUERY_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_LINKS})

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_SKIP_RPATH TRUE)

# A final map from CMake build platform to a enum using for runtime detection.
# The goal is to provide a minimum set of compile code paths.
# See ./include/core.h for the enum class.
# POSIX   = 0x01
# WINDOWS = 0x02
# BSD     = 0x04
# LINUX   = 0x08 && POSIX
# OS X    = 0x10 && BSD && POSIX
# FREEBSD = 0x20 && BSD && POSIX
if(WINDOWS)
  math(EXPR PLATFORM_MASK "2")
elseif(LINUX)
  math(EXPR PLATFORM_MASK "1 + 8")
elseif(APPLE)
  math(EXPR PLATFORM_MASK "1 + 4 + 16")
elseif(FREEBSD)
  math(EXPR PLATFORM_MASK "1 + 4 + 32")
endif()

# Create the static libosquery (everything but non-utility tables).
set(OSQUERY_LIBRARY_FLAGS
  -DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}
  -DOSQUERY_PLATFORM_MASK=${PLATFORM_MASK}
  ${CXX_COMPILE_FLAGS}
)
JOIN("${OSQUERY_LIBRARY_FLAGS}" " " OSQUERY_LIBRARY_FLAGS)

add_library(libosquery STATIC main/lib.cpp ${OSQUERY_OBJECTS})
target_link_libraries(libosquery ${OSQUERY_LIBS})
set_target_properties(libosquery PROPERTIES OUTPUT_NAME osquery)
set_target_properties(libosquery PROPERTIES COMPILE_FLAGS "${OSQUERY_LIBRARY_FLAGS}")

# Create the dynamic libosquery.
if(DEFINED ENV{OSQUERY_BUILD_SHARED})
  add_library(libosquery_shared SHARED main/lib.cpp ${OSQUERY_OBJECTS})
  target_link_libraries(libosquery_shared PRIVATE ${OSQUERY_LIBS})
  set_target_properties(libosquery_shared PROPERTIES COMPILE_FLAGS "${OSQUERY_LIBRARY_FLAGS}")
  set_target_properties(libosquery_shared PROPERTIES OUTPUT_NAME osquery)
endif()

# A friendly echo printed after the library is built.
add_custom_target(osquery_library ALL
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
    "-- Built libosquery: $<TARGET_FILE:libosquery>"
  DEPENDS libosquery
)

# make devel (implies install)
add_custom_target(devel
  COMMAND ${CMAKE_COMMAND} -D COMPONENT=devel -P cmake_install.cmake
  DEPENDS libosquery_basic
)
add_dependencies(devel libosquery)

if(NOT OSQUERY_BUILD_SDK_ONLY)
  if(NOT SKIP_TABLES)
    # Generate the osquery additional tables (the non-util).
    GENERATE_TABLES("${CMAKE_SOURCE_DIR}")
    AMALGAMATE("${CMAKE_SOURCE_DIR}" "additional" AMALGAMATION)
    ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_additional_amalgamation ${AMALGAMATION})
  endif()

  AMALGAMATE("${CMAKE_SOURCE_DIR}" "foreign" AMALGAMATION_FOREIGN)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_foreign_amalgamation ${AMALGAMATION_FOREIGN})

  # Create the static libosquery_additional.
  add_library(libosquery_additional STATIC ${OSQUERY_ADDITIONAL_SOURCES})
  target_link_libraries(libosquery_additional ${OSQUERY_ADDITIONAL_LINKS})
  set_target_properties(libosquery_additional PROPERTIES OUTPUT_NAME osquery_additional)

  # Create the dynamic libosquery_additional.
  if(DEFINED ENV{OSQUERY_BUILD_SHARED})
    add_library(libosquery_additional_shared SHARED ${OSQUERY_ADDITIONAL_SOURCES})
    target_link_libraries(libosquery_additional_shared PRIVATE ${OSQUERY_ADDITIONAL_LINKS})
    set_target_properties(libosquery_additional_shared PROPERTIES OUTPUT_NAME osquery_additional)
  endif()

  add_executable(shell devtools/shell.cpp main/shell.cpp)
  ADD_DEFAULT_LINKS(shell TRUE)
  SET_OSQUERY_COMPILE(shell "${CXX_COMPILE_FLAGS}")
  target_link_libraries(shell)
  set_target_properties(shell PROPERTIES OUTPUT_NAME osqueryi)

  add_executable(daemon main/${PROCESS_FAMILY}/daemon.cpp)
  ADD_DEFAULT_LINKS(daemon TRUE)
  SET_OSQUERY_COMPILE(daemon "${CXX_COMPILE_FLAGS}")
  set_target_properties(daemon PROPERTIES OUTPUT_NAME osqueryd)

  # Include the public API includes if make devel.
  install(TARGETS libosquery ARCHIVE DESTINATION lib COMPONENT devel OPTIONAL)
  install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/osquery"
    DESTINATION include
    COMPONENT devel OPTIONAL
    PATTERN ".*" EXCLUDE
  )

  # A friendly echo printed before building the shell
  add_custom_command(TARGET shell PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
      "-- Building osqueryi: $<TARGET_FILE:shell>"
  )

  # A friendly echo printed before building the daemon
  add_custom_command(TARGET daemon PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
      "-- Building osqueryd: $<TARGET_FILE:daemon>"
  )

  # make install (executables)
  install(TARGETS shell RUNTIME DESTINATION bin COMPONENT main)
  install(TARGETS daemon RUNTIME DESTINATION bin COMPONENT main)
  install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryctl"
    DESTINATION bin COMPONENT main)

  # make install (config files)
  install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  install(DIRECTORY DESTINATION "${CMAKE_INSTALL_PREFIX}/var/osquery")

  install(DIRECTORY "${CMAKE_SOURCE_DIR}/packs/"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/packs" COMPONENT main)
  if(APPLE)
    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/com.facebook.osqueryd.plist"
      DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  else()
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.initd"
      DESTINATION "/etc/init.d/" RENAME "osqueryd" COMPONENT main)
  endif()
endif()

if(NOT SKIP_TESTS)
  # osquery testing library (testing helper methods/libs).
  add_library(libosquery_testing STATIC tests/test_util.cpp)
  add_dependencies(libosquery_testing libosquery)
  SET_OSQUERY_COMPILE(libosquery_testing "${CXX_COMPILE_FLAGS}")
  set_target_properties(libosquery_testing PROPERTIES OUTPUT_NAME osquery_testing)

  # osquery core set of unit tests build with SDK.
  add_executable(osquery_tests main/tests.cpp ${OSQUERY_TESTS})
  ADD_DEFAULT_LINKS(osquery_tests FALSE)
  target_link_libraries(osquery_tests gtest gmock libosquery_testing)
  SET_OSQUERY_COMPILE(osquery_tests "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS}")
  add_test(osquery_tests osquery_tests)

  # osquery kernel tests.
  if(NOT ${OSQUERY_BUILD_SDK_ONLY} AND NOT WINDOWS)
    add_executable(osquery_kernel_tests main/tests.cpp ${OSQUERY_KERNEL_TESTS})
    ADD_DEFAULT_LINKS(osquery_kernel_tests TRUE)
    target_link_libraries(osquery_kernel_tests gtest gmock libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_kernel_tests "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS} -DKERNEL_TEST=1")
  endif()

  # osquery benchmarks.
  if(NOT SKIP_BENCHMARKS AND NOT OSQUERY_BUILD_SDK_ONLY)
    add_executable(osquery_benchmarks main/benchmarks.cpp ${OSQUERY_BENCHMARKS})
    target_link_libraries(osquery_benchmarks benchmark libosquery_testing pthread)
    ADD_DEFAULT_LINKS(osquery_benchmarks TRUE)
    SET_OSQUERY_COMPILE(osquery_benchmarks "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS}")
    set(BENCHMARK_TARGET "$<TARGET_FILE:osquery_benchmarks>")

    # osquery kernel benchmarks.
    add_executable(osquery_kernel_benchmarks main/benchmarks.cpp ${OSQUERY_KERNEL_BENCHMARKS})
    target_link_libraries(osquery_kernel_benchmarks benchmark libosquery_testing pthread)
    ADD_DEFAULT_LINKS(osquery_kernel_benchmarks TRUE)
    SET_OSQUERY_COMPILE(osquery_kernel_benchmarks "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS} -DKERNEL_TEST=1")

    # make benchmark
    add_custom_target(
      run-benchmark
      COMMAND bash -c "${BENCHMARK_TARGET} $ENV{BENCHMARK_TO_FILE}"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      DEPENDS osquery_benchmarks
    )
  endif()

  if(NOT OSQUERY_BUILD_SDK_ONLY)
    # osquery core (additional) set of unit tests built outside of SDK.
    add_executable(osquery_additional_tests tests/test_additional_util.cpp main/tests.cpp ${OSQUERY_ADDITIONAL_TESTS})
    ADD_DEFAULT_LINKS(osquery_additional_tests TRUE)
    target_link_libraries(osquery_additional_tests gtest gmock libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_additional_tests "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS}")
    add_test(osquery_additional_tests osquery_additional_tests)

    # osquery tables set of unit tests (extracted for organization).
    add_executable(osquery_tables_tests main/tests.cpp ${OSQUERY_TABLES_TESTS})
    ADD_DEFAULT_LINKS(osquery_tables_tests TRUE)
    target_link_libraries(osquery_tables_tests gtest gmock libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_tables_tests "${GTEST_FLAGS} ${CXX_COMPILE_FLAGS}")
    add_test(osquery_tables_tests osquery_tables_tests)
  endif()

  # Build the example extension with the SDK.
  ADD_OSQUERY_EXTENSION(example_extension examples/example_extension.cpp)
endif()
