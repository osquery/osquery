# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.14.6)

option(OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS "This option can be enable to show all warnings in the source modules. Not recommended" OFF)

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

function(patchSubmoduleSourceCode patches_dir source_dir apply_to_dir)
  file(GLOB submodule_patches "${patches_dir}/*.patch")

  list(LENGTH submodule_patches patches_num)

  if(NOT patches_num GREATER 0)
    set(patchSubmoduleSourceCode_Patched FALSE PARENT_SCOPE)
    return()
  endif()

  find_package(Git REQUIRED)

  # We patch the submodule before moving it to the binary folder
  # because if git apply working directory is inside a repository or submodule
  # and it's not its root directory, patching will fail silently.
  # This can happen for instance when the build directory is inside the source directory.
  foreach(patch ${submodule_patches})
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply "${patch}"
      RESULT_VARIABLE process_exit_code
      WORKING_DIRECTORY "${source_dir}"
    )

    if(NOT ${process_exit_code} EQUAL 0)
      message(FATAL_ERROR "Failed to patch the following git submodule: \"${apply_to_dir}\"")
    endif()
  endforeach()

  # Move the patched sources to another location because some submodules
  # have symbolic link loops which cannot be correctly copied.
  get_filename_component(parent_dir "${apply_to_dir}" DIRECTORY)

  execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${parent_dir}")
  execute_process(COMMAND "${CMAKE_COMMAND}" -E rename "${source_dir}" "${apply_to_dir}")

  set(patchSubmoduleSourceCode_Patched TRUE PARENT_SCOPE)
endfunction()

function(importSourceSubmodule)
  cmake_parse_arguments(
    ARGS
    "NO_RECURSIVE"
    "NAME"
    "SUBMODULES;SHALLOW_SUBMODULES;PATCH"
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
  endforeach()

  foreach(submodule_to_patch ${ARGS_PATCH})
    set(patched_source_dir "${CMAKE_BINARY_DIR}/libs/src/patched-source/${ARGS_NAME}/${submodule_to_patch}")

    set(library_name "${ARGS_NAME}")

    if (NOT "${submodule_to_patch}" STREQUAL "src")
      set(library_name "${library_name}_${submodule_to_patch}")
    endif()

    string(REPLACE "/" "_" library_name "${library_name}")

    set(OSQUERY_${library_name}_ROOT_DIR "${patched_source_dir}")

    if(NOT EXISTS "${patched_source_dir}")
      patchSubmoduleSourceCode(
        "${directory_path}/patches/${submodule_to_patch}"
        "${directory_path}/${submodule_to_patch}"
        "${patched_source_dir}"
      )

      if(patchSubmoduleSourceCode_Patched)
        list(FIND ARGS_SHALLOW_SUBMODULES "${submodule_to_patch}" shallow_clone)
        if(${shallow_clone} EQUAL -1)
          set(shallow_clone false)
        else()
          set(shallow_clone true)
        endif()

        initializeGitSubmodule("${directory_path}/${submodule_to_patch}" ${ARGS_NO_RECURSIVE} ${shallow_clone})
      endif()
    endif()
  endforeach()

  if(NOT OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS)
    if(DEFINED PLATFORM_POSIX)
      target_compile_options(osquery_thirdparty_extra_c_settings INTERFACE
        -Wno-everything -Wno-all -Wno-error
      )
      target_compile_options(osquery_thirdparty_extra_cxx_settings INTERFACE
        -Wno-everything -Wno-all -Wno-error
      )
    elseif(DEFINED PLATFORM_WINDOWS)
      target_compile_options(osquery_thirdparty_extra_c_settings INTERFACE
        /W0
      )
      target_compile_options(osquery_thirdparty_extra_cxx_settings INTERFACE
        /W0
      )
    endif()
  endif()

  # Make sure we don't run clang-tidy on the source modules
  unset(CMAKE_C_CLANG_TIDY)
  unset(CMAKE_CXX_CLANG_TIDY)

  add_subdirectory(
    "${directory_path}"
    "${CMAKE_BINARY_DIR}/libs/src/${ARGS_NAME}"
  )
endfunction()
