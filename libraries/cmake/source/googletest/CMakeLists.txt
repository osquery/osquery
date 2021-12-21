# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(googleTestMain)
  set(disabled_option_list
    INSTALL_GTEST
    gmock_build_tests
    gtest_build_samples
    gtest_build_tests
    gtest_disable_pthreads
    gtest_force_shared_crt
    gtest_hide_internal_symbols
  )

  foreach(option_name ${disabled_option_list})
    set("${option_name}" false CACHE BOOL "" FORCE)
  endforeach()

  set(enabled_option_list
    BUILD_GMOCK
  )

  foreach(option_name ${enabled_option_list})
    set("${option_name}" true CACHE BOOL "" FORCE)
  endforeach()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  set(target_list
    gmock
    gtest
    gtest_main
  )

  foreach(target_name ${target_list})
    target_link_libraries("${target_name}" PRIVATE
      thirdparty_cxx_settings
    )

    if(DEFINED PLATFORM_WINDOWS)
      get_target_property(target_compile_flags ${target_name} COMPILE_FLAGS)
      string(REPLACE "-Zi" "-Z7" target_compile_flags "${target_compile_flags}")
      set_target_properties(${target_name} PROPERTIES COMPILE_FLAGS ${target_compile_flags})
    endif()
  endforeach()

  add_library(thirdparty_googletest INTERFACE)
  target_link_libraries(thirdparty_googletest INTERFACE
    ${target_list}
  )

  get_target_property(googletest_include_dirs gtest INTERFACE_INCLUDE_DIRECTORIES)

  add_library(thirdparty_googletest_headers INTERFACE)
  target_include_directories(thirdparty_googletest_headers SYSTEM INTERFACE
    "${googletest_include_dirs}"
  )
endfunction()

googleTestMain()
