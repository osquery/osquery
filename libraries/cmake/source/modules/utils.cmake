# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.14.6)

option(OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS "This option can be enable to show all warnings in the source modules. Not recommended" OFF)

function(getGitExecutableName output_variable)
  set(output "git")
  if(DEFINED PLATFORM_WINDOWS)
    set(output "${output}.exe")
  endif()

  set("${output_variable}" "${output}" PARENT_SCOPE)
endfunction()

function(locateGitExecutable output_variable)
  getGitExecutableName(git_executable_name)

  find_program(git_path "${git_executable_name}")
  if("${git_path}" STREQUAL "git_path-NOTFOUND")
    set("${output_variable}" "git_path-NOTFOUND" PARENT_SCOPE)

  else()
    set("${output_variable}" "${git_path}" PARENT_SCOPE)
  endif()
endfunction()

function(initializeGitSubmodule submodule_path no_recursive shallow)
  file(GLOB submodule_folder_contents "${submodule_path}/*")

  list(LENGTH submodule_folder_contents submodule_folder_file_count)
  if(NOT ${submodule_folder_file_count} EQUAL 0)
    set(initializeGitSubmodule_IsAlreadyCloned TRUE PARENT_SCOPE)
    return()
  endif()

  find_package(Git REQUIRED)

  if(no_recursive)
    set(optional_recursive_arg "")
  else()
    set(optional_recursive_arg "--recursive")
  endif()

  if(shallow)
    set(optional_depth_arg "--depth=1")
  else()
    set(optional_depth_arg "")
  endif()

  get_filename_component(working_directory "${submodule_path}" DIRECTORY)

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" submodule update --init ${optional_recursive_arg} ${optional_depth_arg} "${submodule_path}"
    RESULT_VARIABLE process_exit_code
    WORKING_DIRECTORY "${working_directory}"
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to update the following git submodule: \"${submodule_path}\"")
  endif()

  set(initializeGitSubmodule_IsAlreadyCloned FALSE PARENT_SCOPE)
endfunction()

function(patchSubmoduleSourceCode patches_dir apply_to_dir)
  file(GLOB submodule_patches "${patches_dir}/*.patch")

  foreach(patch ${submodule_patches})
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply "${patch}"
      RESULT_VARIABLE process_exit_code
      WORKING_DIRECTORY "${apply_to_dir}"
    )

    if(NOT ${process_exit_code} EQUAL 0)
      message(FATAL_ERROR "Failed to patch the following git submodule: \"${apply_to_dir}\"")
    endif()
  endforeach()
endfunction()

function(importSourceSubmodule)
  cmake_parse_arguments(
    ARGS
    "NO_RECURSIVE"
    "NAME"
    "SUBMODULES;SHALLOW_SUBMODULES"
    ${ARGN}
  )

  if("${ARGS_NAME}" STREQUAL "modules")
    message(FATAL_ERROR "Invalid library name specified: ${ARGS_NAME}")
  endif()

  message(STATUS "Importing: source/${ARGS_NAME}")

  if("${ARGS_SUBMODULES};${SHALLOW_SUBMODULES}" STREQUAL "")
    message(FATAL_ERROR "Missing git submodule name(s)")
  endif()

  set(directory_path "${CMAKE_SOURCE_DIR}/libraries/cmake/source/${ARGS_NAME}")

  foreach(submodule_name ${ARGS_SUBMODULES} ${ARGS_SHALLOW_SUBMODULES})
    list(FIND ARGS_SHALLOW_SUBMODULES "${submodule_name}" shallow_clone)
    if(${shallow_clone} EQUAL -1)
      set(shallow_clone false)
    else()
      set(shallow_clone true)
    endif()

    initializeGitSubmodule("${directory_path}/${submodule_name}" ${ARGS_NO_RECURSIVE} ${shallow_clone})

    if(NOT initializeGitSubmodule_IsAlreadyCloned)
      patchSubmoduleSourceCode("${directory_path}/patches/${submodule_name}" "${directory_path}/${submodule_name}")
    endif()
  endforeach()

  if(NOT OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS)
    target_compile_options(osquery_thirdparty_extra_c_settings INTERFACE
      -Wno-everything -Wno-all -Wno-error
    )
    target_compile_options(osquery_thirdparty_extra_cxx_settings INTERFACE
      -Wno-everything -Wno-all -Wno-error
    )
  endif()

  add_subdirectory(
    "${directory_path}"
    "${CMAKE_BINARY_DIR}/libs/src/${ARGS_NAME}"
  )
endfunction()
