# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include(ExternalProject)

set(OSQUERY_FORMULA_INSTALL_DIRECTORY "${CMAKE_BINARY_DIR}/installed_formulas")

set(OSQUERY_FORMULA_BUILD_JOBS 4 CACHE STRING "Numer of parallel jobs that will be used for each third party library which uses the formula system to build")


function(importFormula library_name)
  if("${library_name}" STREQUAL "modules")
    message(FATAL_ERROR "Invalid library name specified: ${library_name}")
  endif()

  message(STATUS "Importing formula: formula/${library_name}")

  set(project_directory_path "${CMAKE_SOURCE_DIR}/libraries/cmake/formula/${library_name}")
  set(build_directory_path "${CMAKE_CURRENT_BINARY_DIR}/${library_name}")
  set(install_prefix "${OSQUERY_FORMULA_INSTALL_DIRECTORY}/${library_name}")

  getCompilationFlags(c OSQUERY_FORMULA_CFLAGS)
  getCompilationFlags(cxx OSQUERY_FORMULA_CXXFLAGS)

  add_subdirectory("${project_directory_path}" "${build_directory_path}")
endfunction()

function(getCompilationFlags language output_variable)
  if("${language}" STREQUAL "c")
    set(target_name "thirdparty_c_settings")

  elseif("${language}" STREQUAL "cxx")
    set(target_name "thirdparty_cxx_settings")

  else()
    message(FATAL_ERROR "Invalid language specified. Valid options are c and cxx")
  endif()

  collectInterfaceOptionsFromTarget(TARGET ${target_name} COMPILE compile_options DEFINES compile_definitions)

  list(APPEND compile_flags ${compile_options})
  list(TRANSFORM compile_definitions PREPEND -D)
  list(APPEND compile_flags ${compile_definitions})

  set(${output_variable} "${compile_flags}" PARENT_SCOPE)
endfunction()
