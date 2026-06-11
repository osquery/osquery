set(OSQUERY_TOOLCHAIN_SYSROOT "" CACHE PATH "Path to the sysroot that contains the custom toolchain to use to compile osquery. Linux only.")

if(OSQUERY_TOOLCHAIN_SYSROOT)
  overwrite_cache_variable("CMAKE_C_COMPILER" "STRING" "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin/clang")
  overwrite_cache_variable("CMAKE_CXX_COMPILER" "STRING" "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin/clang++")
  overwrite_cache_variable("CMAKE_SYSROOT" "PATH" "${OSQUERY_TOOLCHAIN_SYSROOT}")
  overwrite_cache_variable("CMAKE_CXX_LINK_NO_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_CXX_LINK_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_C_LINK_NO_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_C_LINK_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_CXX_FLAGS_INIT" "STRING" "-stdlib=libc++ -gdwarf-4")
  overwrite_cache_variable("CMAKE_C_FLAGS_INIT" "STRING" "-gdwarf-4")
  overwrite_cache_variable("CMAKE_EXE_LINKER_FLAGS" "STRING" "-stdlib=libc++ -lc++abi")
else()
  option(OSQUERY_STATIC_BUILD "Whether to prefer linking static libraries or not")

  overwrite_cache_variable("CMAKE_LINK_SEARCH_START_STATIC" "BOOL" "${OSQUERY_STATIC_BUILD}")
  overwrite_cache_variable("CMAKE_LINK_SEARCH_END_STATIC" "BOOL" "${OSQUERY_STATIC_BUILD}")
endif()


if(APPLE)
  if(NOT DEFINED CMAKE_OSX_SYSROOT OR "${CMAKE_OSX_SYSROOT}" STREQUAL "")
    execute_process(
      COMMAND xcrun --sdk macosx --show-sdk-path
      OUTPUT_VARIABLE osquery_macosx_sysroot
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE osquery_xcrun_result
    )

    if(NOT osquery_xcrun_result EQUAL 0 OR "${osquery_macosx_sysroot}" STREQUAL "")
      message(FATAL_ERROR "Unable to detect the macOS SDK path. Please set CMAKE_OSX_SYSROOT.")
    endif()

    set(CMAKE_OSX_SYSROOT "${osquery_macosx_sysroot}" CACHE PATH "Path to the macOS SDK" FORCE)
    unset(osquery_macosx_sysroot)
    unset(osquery_xcrun_result)
  endif()

  message(STATUS "Calculated macOS sysroot: ${CMAKE_OSX_SYSROOT}")

  if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS deployment target")
  endif()

  if(NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER "clang" CACHE STRING "C compiler")
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER "clang++" CACHE STRING "C++ compiler")
  endif()
endif()