# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# - osquery external project builds
# Symlink directories for extensions or modules here.
# If a directory includes: "extension_NAME" it is built as an extension.
# If a directory includes: "module_NAME" it is built as a module.

add_custom_target(externals)

include(cmake/cmakelibs.cmake)

set(EXTERNALS_DIR "${CMAKE_SOURCE_DIR}/external")

add_library(external_options INTERFACE)
target_compile_options(external_options INTERFACE -DOSQUERY_EXTERNAL)
target_link_libraries(external_options INTERFACE
  osquery_cxx_settings
  osquery_sdk_pluginsdk
  osquery_extensions_implthrift
)

function(subdirlist output path)
  file(GLOB children RELATIVE ${path} "${path}/*")
  set(DIRS "")
  foreach(child ${children})
    if("${child}" STREQUAL "examples")
      continue()
    endif()

    get_filename_component(full_child "${path}/${child}" REALPATH)
    if(IS_DIRECTORY "${full_child}")
      list(APPEND DIRS "${path}/${child}")
    elseif(NOT "${child}" STREQUAL "CMakeLists.txt")
      message(WARNING "External project: ${full_child} must be a directory")
    endif()
  endforeach()
  set(${output} ${DIRS} PARENT_SCOPE)
endfunction()

function(externalsExamples)
  set(example_name_list
    "config_plugin"
    "read_only_table"
    "writable_table"
  )

  foreach(example_name ${example_name_list})
    add_subdirectory("examples/${example_name}")
  endforeach()
endfunction()

function(externalsMain)
  externalsExamples()

  # Discover the implementation for extensions or modules in external directory
  subdirlist(EXTERNAL_PROJECTS ${EXTERNALS_DIR})

  # Each project may:
  #   1. Be named "external_PROJECT_NAME", all .cpp, .c, .mm files will be compiled.
  #   2. Be named "module_PROJECT_NAME", the same applies.
  #   3. Contain a "CMakeLists.txt", the project will be added to CMake's evaluation.
  foreach(external_project ${EXTERNAL_PROJECTS})
    get_filename_component(PROJECT_NAME "${external_project}" NAME)
    # check for the cmake having utilities functions
    if(${PROJECT_NAME} MATCHES "cmake")
      continue()
    endif()
    if(EXISTS "${external_project}/CMakeLists.txt")
      add_subdirectory("${external_project}")
    else()
      file(GLOB_RECURSE PROJECT_FILES "${external_project}/*")
      set(PROJECT_SOURCES "")
      foreach(source ${PROJECT_FILES})
        if(${source} MATCHES "^.*(cpp|c|mm)$")
          list(APPEND PROJECT_SOURCES ${source})
        endif()
      endforeach()
      if("${PROJECT_NAME}" MATCHES "(^extension_.*)")
        addOsqueryExtension(external_${PROJECT_NAME} ${PROJECT_SOURCES})
        add_dependencies(externals external_${PROJECT_NAME})
      elseif("${PROJECT_NAME}" MATCHES "(^module_.*)")
        addOsqueryModule(external_${PROJECT_NAME} ${PROJECT_SOURCES})
        add_dependencies(externals external_${PROJECT_NAME})
      else()
        message(WARNING "External project: ${external_project} is incorrectly named")
      endif()
    endif()
  endforeach()
endfunction()

externalsMain()