# osquery core source files included with the SDK (libosquery).
set(OSQUERY_SOURCES "")
set(OSQUERY_LINKS "")
set(OSQUERY_TESTS "")
set(OSQUERY_KERNEL_TESTS "")

# osquery benchmarking sources
set(OSQUERY_BENCHMARKS "")
set(OSQUERY_KERNEL_BENCHMARKS "")

# osquery core additional sources files not included with SDK (libosquery_additional).
set(OSQUERY_ADDITIONAL_SOURCES "")
set(OSQUERY_ADDITIONAL_LINKS "")
set(OSQUERY_ADDITIONAL_TESTS "")
set(OSQUERY_TABLES_TESTS "")

# The core set of osquery libraries most discovered with find_package.
set(OSQUERY_LIBS
  # This includes librocksdb[_lite] and libsnappy.
  ${ROCKSDB_LIBRARIES}
  ${THRIFT_LIBRARY}
  ${GLOG_LIBRARY}
  ${GFLAGS_LIBRARY}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_SSL_LIBRARY}
  ${READLINE_LIBRARIES}

  pthread
  bz2
  z
)

# Add all and extra for osquery code.
add_compile_options(
  -Wall
  -Wextra
  -Wno-unused-parameter
)

if(NOT FREEBSD)
  set(OSQUERY_LIBS ${OSQUERY_LIBS} dl)
else()
  ADD_OSQUERY_LINK_CORE("icuuc")
endif()

# Add default linking details (the first argument means SDK + core).
ADD_OSQUERY_LINK_CORE("-rdynamic")
foreach(DISTRO ${OSQUERY_REQUIRE_RUNTIMES})
  if(${OSQUERY_BUILD_DISTRO} STREQUAL ${DISTRO})
    ADD_OSQUERY_LINK_ADDITIONAL("-static-libstdc++")
  endif()
endforeach()

# The platform-specific SDK + core libraries.
if(APPLE)
  ADD_OSQUERY_LINK_CORE("-Wl,-dead_strip")
  ADD_OSQUERY_LINK_CORE("-mmacosx-version-min=${OSX_VERSION_MIN}")
  ADD_OSQUERY_LINK_CORE("boost_thread-mt")
  ADD_OSQUERY_LINK_CORE("lz4")
else()
  ADD_OSQUERY_LINK_CORE("-Wl,-zrelro -Wl,-znow")
  if(NOT ${OSQUERY_BUILD_DISTRO} STREQUAL "rhel6" AND
     NOT ${OSQUERY_BUILD_DISTRO} STREQUAL "centos6")
    ADD_OSQUERY_LINK_CORE("-Wl,--gc-sections")
  endif()
  ADD_OSQUERY_LINK_CORE("boost_thread")
  ADD_OSQUERY_LINK_CORE("librt.so")
endif()

# The remaining boost libraries are discovered with find_library.
ADD_OSQUERY_LINK_CORE("boost_system")
ADD_OSQUERY_LINK_CORE("boost_filesystem")
ADD_OSQUERY_LINK_CORE("boost_regex")
ADD_OSQUERY_LINK_CORE("yara")

# Remaining additional development libraries.
ADD_OSQUERY_LINK_ADDITIONAL("cppnetlib-uri")
ADD_OSQUERY_LINK_ADDITIONAL("cppnetlib-client-connections")

if(DEFINED ENV{SANITIZE})
  if(DEFINED ENV{SANITIZE_THREAD})
    ADD_OSQUERY_LINK_CORE(-fsanitize=thread)
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
add_subdirectory(remote)
add_subdirectory(sql)

if(NOT ENV{SKIP_TABLES})
  add_subdirectory(tables)
endif()

# Amalgamate the utility tables needed to compile.
GENERATE_UTILITIES("${CMAKE_SOURCE_DIR}")
AMALGAMATE("${CMAKE_SOURCE_DIR}" "utils" AMALGAMATION_UTILS)
ADD_OSQUERY_LIBRARY_CORE(osquery_amalgamation ${AMALGAMATION_UTILS})

# Bubble the subdirectory (component) sources and links for this build.
list(APPEND OSQUERY_OBJECTS ${OSQUERY_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_LINKS})

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_SKIP_RPATH TRUE)

# Create the static libosquery (everything but non-utility tables).
add_library(libosquery STATIC main/lib.cpp ${OSQUERY_OBJECTS})
target_link_libraries(libosquery ${OSQUERY_LIBS})
set_target_properties(libosquery PROPERTIES OUTPUT_NAME osquery)
set_target_properties(libosquery PROPERTIES COMPILE_FLAGS
  "-DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION} ${CXX_COMPILE_FLAGS}")

# A friendly echo printed after the library is built.
add_custom_target(osquery_library ALL
  DEPENDS libosquery
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
    "-- Built libosquery: ${CMAKE_BINARY_DIR}/libosquery.a"
)

# make devel (implies install)
add_custom_target(devel
  COMMAND ${CMAKE_COMMAND}
    -D COMPONENT=devel
    -P cmake_install.cmake
    DEPENDS libosquery_basic
)
add_dependencies(devel libosquery)

if(NOT OSQUERY_BUILD_SDK_ONLY)
  # Generate the osquery additional tables (the non-util).
  GENERATE_TABLES("${CMAKE_SOURCE_DIR}")
  AMALGAMATE("${CMAKE_SOURCE_DIR}" "additional" AMALGAMATION)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_additional_amalgamation ${AMALGAMATION})

  # Create the static libosquery_additional.
  add_library(libosquery_additional STATIC ${OSQUERY_ADDITIONAL_SOURCES})
  target_link_libraries(libosquery_additional ${OSQUERY_ADDITIONAL_LINKS})
  set_target_properties(libosquery_additional PROPERTIES OUTPUT_NAME osquery_additional)

  add_executable(shell devtools/shell.cpp main/shell.cpp)
  TARGET_OSQUERY_LINK_WHOLE(shell libosquery)
  TARGET_OSQUERY_LINK_WHOLE(shell libosquery_additional)
  SET_OSQUERY_COMPILE(shell "${CXX_COMPILE_FLAGS}")
  set_target_properties(shell PROPERTIES OUTPUT_NAME osqueryi)

  add_executable(daemon main/daemon.cpp)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery_additional)
  SET_OSQUERY_COMPILE(daemon "${CXX_COMPILE_FLAGS}")
  set_target_properties(daemon PROPERTIES OUTPUT_NAME osqueryd)

  # Include the public API includes if make devel.
  install(TARGETS libosquery ARCHIVE DESTINATION lib COMPONENT devel OPTIONAL)
  install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/osquery"
    DESTINATION include
    COMPONENT devel OPTIONAL
    PATTERN ".*" EXCLUDE
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

if(NOT DEFINED ENV{SKIP_TESTS})
  # osquery testing library (testing helper methods/libs).
  add_library(libosquery_testing STATIC core/test_util.cpp)
  add_dependencies(libosquery_testing libosquery)
  SET_OSQUERY_COMPILE(libosquery_testing "${CXX_COMPILE_FLAGS}")
  set_target_properties(libosquery_testing PROPERTIES OUTPUT_NAME osquery_testing)

  # osquery core set of unit tests build with SDK.
  add_executable(osquery_tests main/tests.cpp ${OSQUERY_TESTS})
  TARGET_OSQUERY_LINK_WHOLE(osquery_tests libosquery)
  target_link_libraries(osquery_tests gtest libosquery_testing)
  SET_OSQUERY_COMPILE(osquery_tests "${CXX_COMPILE_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
  add_test(osquery_tests osquery_tests)

  # osquery kernel tests.
  add_executable(osquery_kernel_tests main/tests.cpp ${OSQUERY_KERNEL_TESTS})
  TARGET_OSQUERY_LINK_WHOLE(osquery_kernel_tests libosquery)
  TARGET_OSQUERY_LINK_WHOLE(osquery_kernel_tests libosquery_additional)
  target_link_libraries(osquery_kernel_tests gtest libosquery_testing)
  SET_OSQUERY_COMPILE(osquery_kernel_tests "${CXX_COMPILE_FLAGS} -DKERNEL_TEST=1 -DGTEST_HAS_TR1_TUPLE=0")

  # osquery benchmarks.
  if(NOT DEFINED ENV{SKIP_BENCHMARKS})
    add_executable(osquery_benchmarks main/benchmarks.cpp ${OSQUERY_BENCHMARKS})
    TARGET_OSQUERY_LINK_WHOLE(osquery_benchmarks libosquery)
    TARGET_OSQUERY_LINK_WHOLE(osquery_benchmarks libosquery_additional)
    target_link_libraries(osquery_benchmarks benchmark libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_benchmarks "${CXX_COMPILE_FLAGS}")
    set(BENCHMARK_TARGET "$<TARGET_FILE:osquery_benchmarks>")

    # osquery kernel benchmarks.
    add_executable(osquery_kernel_benchmarks main/benchmarks.cpp ${OSQUERY_KERNEL_BENCHMARKS})
    TARGET_OSQUERY_LINK_WHOLE(osquery_kernel_benchmarks libosquery)
    TARGET_OSQUERY_LINK_WHOLE(osquery_kernel_benchmarks libosquery_additional)
    target_link_libraries(osquery_kernel_benchmarks benchmark libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_kernel_benchmarks "${CXX_COMPILE_FLAGS} -DKERNEL_TEST=1")

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
    add_executable(osquery_additional_tests main/tests.cpp ${OSQUERY_ADDITIONAL_TESTS})
    TARGET_OSQUERY_LINK_WHOLE(osquery_additional_tests libosquery)
    TARGET_OSQUERY_LINK_WHOLE(osquery_additional_tests libosquery_additional)
    target_link_libraries(osquery_additional_tests gtest libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_additional_tests "${CXX_COMPILE_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
    add_test(osquery_additional_tests osquery_additional_tests)

    # osquery tables set of unit tests (extracted for organization).
    add_executable(osquery_tables_tests main/tests.cpp ${OSQUERY_TABLES_TESTS})
    TARGET_OSQUERY_LINK_WHOLE(osquery_tables_tests libosquery)
    TARGET_OSQUERY_LINK_WHOLE(osquery_tables_tests libosquery_additional)
    target_link_libraries(osquery_tables_tests gtest libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_tables_tests "${CXX_COMPILE_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
    add_test(osquery_tables_tests osquery_tables_tests)
  endif()

  # Build the example extension with the SDK.
  ADD_OSQUERY_EXTENSION(example_extension examples/example_extension.cpp)

  # Build the example extension module with the SDK.
  ADD_OSQUERY_MODULE(modexample examples/example_module.cpp)
endif()
