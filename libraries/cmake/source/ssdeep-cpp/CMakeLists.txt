# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(ssdeepCppMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_ssdeep-cpp INTERFACE)

  add_library(thirdparty_ssdeep-cpp_cpp
    "${library_root}/match.cpp"
    "${library_root}/engine.cpp"
    "${library_root}/filedata.cpp"
    "${library_root}/dig.cpp"
    "${library_root}/cycles.cpp"
    "${library_root}/helpers.cpp"
    "${library_root}/ui.cpp"
  )

  add_library(thirdparty_ssdeep-cpp_c
    "${library_root}/fuzzy.c"
    "${library_root}/find-file-size.c"
  )

  target_compile_definitions(thirdparty_ssdeep-cpp_cpp PRIVATE
    HAVE_CONFIG_H
  )

  target_compile_definitions(thirdparty_ssdeep-cpp_c PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_ssdeep-cpp_cpp PRIVATE
    thirdparty_cxx_settings
  )

  target_link_libraries(thirdparty_ssdeep-cpp_c PRIVATE
    thirdparty_c_settings
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_ssdeep-cpp_cpp PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )

    target_include_directories(thirdparty_ssdeep-cpp_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_ssdeep-cpp_cpp PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )

    target_include_directories(thirdparty_ssdeep-cpp_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  endif()

  target_include_directories(thirdparty_ssdeep-cpp_cpp PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_ssdeep-cpp_c PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_ssdeep-cpp SYSTEM INTERFACE
    "${library_root}"
  )

  target_link_libraries(thirdparty_ssdeep-cpp INTERFACE
    thirdparty_ssdeep-cpp_cpp
    thirdparty_ssdeep-cpp_c
  )
endfunction()

ssdeepCppMain()
