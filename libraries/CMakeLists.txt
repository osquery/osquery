# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(librariesMain)
  if("${OSQUERY_THIRD_PARTY_SOURCE}" STREQUAL "")
    message(STATUS "Disabling local third-party sources. Using system libraries")
    return()
  endif()

  foreach(source ${OSQUERY_THIRD_PARTY_SOURCE})
    set(third_party_source_path "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${source}/modules")
    if(NOT EXISTS "${third_party_source_path}")
      message(WARNING "Invalid third-party source setting: ${source}")
      continue()
    endif()

    list(APPEND module_path_list "${third_party_source_path}")
  endforeach()

  list(INSERT module_path_list 0 ${CMAKE_MODULE_PATH})
  overwrite_cache_variable("CMAKE_MODULE_PATH" STRING "${module_path_list}")

  add_library(thirdparty_cxx_settings INTERFACE)
  add_library(thirdparty_c_settings INTERFACE)

  target_link_libraries(thirdparty_cxx_settings INTERFACE cxx_settings)
  target_link_libraries(thirdparty_c_settings INTERFACE c_settings)

  if(DEFINED PLATFORM_POSIX)
    set(compile_options
      -Oz
      -g0
    )
  endif()

  set(defines
    NDEBUG
  )

  add_library(thirdparty_options INTERFACE)

  target_compile_options(thirdparty_options INTERFACE
    ${compile_options}
  )
  target_compile_definitions(thirdparty_options INTERFACE
    ${defines}
  )

  target_link_libraries(thirdparty_cxx_settings INTERFACE thirdparty_options)
  target_link_libraries(thirdparty_c_settings INTERFACE thirdparty_options)

  add_library(osquery_thirdparty_extra_cxx_settings INTERFACE)
  add_library(osquery_thirdparty_extra_c_settings INTERFACE)
  target_link_libraries(thirdparty_cxx_settings INTERFACE osquery_thirdparty_extra_cxx_settings)
  target_link_libraries(thirdparty_c_settings INTERFACE osquery_thirdparty_extra_c_settings)

endfunction()

librariesMain()
