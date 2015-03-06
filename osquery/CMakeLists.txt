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

# Add default linking details
ADD_OSQUERY_LINK(TRUE "-rdynamic")

# The platform-specific core libraries.
if(APPLE)
  ADD_OSQUERY_LINK(TRUE "-mmacosx-version-min=${APPLE_MIN_ABI}")
  ADD_OSQUERY_LINK(TRUE "boost_thread-mt")
  ADD_OSQUERY_LINK(TRUE "lz4")
else()
  ADD_OSQUERY_LINK(TRUE "-Wl,-zrelro -Wl,-znow")
  ADD_OSQUERY_LINK(TRUE "boost_thread")
  ADD_OSQUERY_LINK(TRUE "rt")
endif()

# The remaining boost libraries are discovered with find_library.
ADD_OSQUERY_LINK(TRUE "boost_system")
ADD_OSQUERY_LINK(TRUE "boost_filesystem")

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
add_subdirectory(scheduler)
add_subdirectory(sql)
add_subdirectory(tables)

# Finally amalgamate the tables needed to compile.
GENERATE_UTILITIES("${CMAKE_SOURCE_DIR}/osquery/tables")
AMALGAMATE("${CMAKE_SOURCE_DIR}" "utils" AMALGAMATION_UTILS)
ADD_OSQUERY_LIBRARY(TRUE osquery_utils_amalgamation ${AMALGAMATION_UTILS})

list(APPEND OSQUERY_OBJECTS ${OSQUERY_SOURCES})
list(APPEND OSQUERY_LIBS ${OSQUERY_LINKS})

# Create the static libosquery (everything but non-util tables).
set(CMAKE_MACOSX_RPATH 0)
add_library(libosquery STATIC main/lib.cpp ${OSQUERY_OBJECTS})
target_link_libraries(libosquery ${OSQUERY_LIBS})
set_target_properties(libosquery PROPERTIES OUTPUT_NAME osquery)

# Also create a static testing library (mostly testing utilities).
add_library(libosquery_testing STATIC core/test_util.cpp)
add_dependencies(libosquery_testing libosquery)
set_target_properties(libosquery_testing PROPERTIES OUTPUT_NAME osquery_testing)
set_target_properties(libosquery_testing PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS}")

add_custom_target(BUILD_LIB_SUCCESS ALL
  DEPENDS libosquery
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "Built libosquery: ${CMAKE_BINARY_DIR}"
)

# make devel (implies install)
add_custom_target(devel
  COMMAND ${CMAKE_COMMAND}
    -D COMPONENT=devel
    -P cmake_install.cmake
    DEPENDS libosquery_basic
)
add_dependencies(devel libosquery)

# Generate the osquery additional tables (the non-util).
GENERATE_TABLES("${CMAKE_SOURCE_DIR}/osquery/tables")
AMALGAMATE("${CMAKE_SOURCE_DIR}" "additional" AMALGAMATION)
ADD_OSQUERY_LIBRARY(FALSE osquery_amalgamation ${AMALGAMATION})

if(NOT OSQUERY_BUILD_SDK_ONLY)
  # Create the static libosquery_additional.
  add_library(libosquery_additional STATIC ${OSQUERY_ADDITIONAL_SOURCES})
  target_link_libraries(libosquery_additional ${OSQUERY_ADDITIONAL_LINKS})
  set_target_properties(libosquery_additional PROPERTIES OUTPUT_NAME osquery_additional)

  add_executable(shell devtools/shell.cpp main/shell.cpp)
  TARGET_OSQUERY_LINK_WHOLE(shell libosquery)
  TARGET_OSQUERY_LINK_WHOLE(shell libosquery_additional)
  set_target_properties(shell PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS}")
  set_target_properties(shell PROPERTIES OUTPUT_NAME osqueryi)

  add_executable(daemon main/daemon.cpp)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery_additional)
  set_target_properties(daemon PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS}")
  set_target_properties(daemon PROPERTIES OUTPUT_NAME osqueryd)

  add_executable(run main/run.cpp)
  TARGET_OSQUERY_LINK_WHOLE(run libosquery)
  TARGET_OSQUERY_LINK_WHOLE(run libosquery_additional)
  set_target_properties(run PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS}")

  # Include the public API includes if make devel.
  install(TARGETS libosquery ARCHIVE DESTINATION lib COMPONENT devel OPTIONAL)
  install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION include COMPONENT devel OPTIONAL)

  # make install (executables)
  install(TARGETS shell RUNTIME DESTINATION bin COMPONENT main)
  install(TARGETS daemon RUNTIME DESTINATION bin COMPONENT main)

  # make install (config files)
  install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  if(APPLE)
    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/com.facebook.osqueryd.plist"
      DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  else()
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.initd"
      DESTINATION "/etc/init.d/" RENAME "osqueryd" COMPONENT main)
  endif()
endif()

# Build the example extension with the SDK
ADD_OSQUERY_EXTENSION(example_extension examples/example_extension.cpp)

# Build the example extension module with the SDK
ADD_OSQUERY_MODULE(modexample examples/example_module.cpp)
