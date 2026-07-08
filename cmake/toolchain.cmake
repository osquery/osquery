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

  message(STATUS "Using macOS sysroot: ${CMAKE_OSX_SYSROOT}")

  if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS deployment target")
  endif()

  if(NOT DEFINED CMAKE_C_COMPILER OR "${CMAKE_C_COMPILER}" STREQUAL "")
    execute_process(
      COMMAND xcrun -find clang
      OUTPUT_VARIABLE osquery_clang_path
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE osquery_xcrun_result
    )

    if(NOT osquery_xcrun_result EQUAL 0 OR "${osquery_clang_path}" STREQUAL "")
      message(FATAL_ERROR "Unable to locate clang via xcrun. Please set CMAKE_C_COMPILER.")
    endif()

    set(CMAKE_C_COMPILER "${osquery_clang_path}" CACHE FILEPATH "C compiler" FORCE)
    unset(osquery_clang_path)
    unset(osquery_xcrun_result)
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER OR "${CMAKE_CXX_COMPILER}" STREQUAL "")
    execute_process(
      COMMAND xcrun -find clang++
      OUTPUT_VARIABLE osquery_clangxx_path
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE osquery_xcrun_result
    )

    if(NOT osquery_xcrun_result EQUAL 0 OR "${osquery_clangxx_path}" STREQUAL "")
      message(FATAL_ERROR "Unable to locate clang++ via xcrun. Please set CMAKE_CXX_COMPILER.")
    endif()

    set(CMAKE_CXX_COMPILER "${osquery_clangxx_path}" CACHE FILEPATH "C++ compiler" FORCE)
    unset(osquery_clangxx_path)
    unset(osquery_xcrun_result)
  endif()
endif()