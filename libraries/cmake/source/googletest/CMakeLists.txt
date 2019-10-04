# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

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
