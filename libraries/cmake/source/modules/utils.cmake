# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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

  set(optional_depth_arg "")
  if(shallow)
    if(GIT_VERSION_STRING VERSION_GREATER_EQUAL "2.14.0")
      set(optional_depth_arg "--depth=1")
    else()
      message(WARNING "Git version >=2.14.0 is required to perform shallow clones, detected version ${GIT_VERSION_STRING}, falling back to full clones (slower).")
    endif()
  endif()

  # In git versions >= 2.18.0 we need to explicitly set the protocol
  # in order to do a shallow clone without error.
  if(GIT_VERSION_STRING VERSION_EQUAL "2.18.0" OR GIT_VERSION_STRING VERSION_GREATER "2.18.0")
    set(optional_protocol_arg -c protocol.version=2)
  else()
    set(optional_protocol_arg "")
  endif()


  get_filename_component(working_directory "${submodule_path}" DIRECTORY)

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" ${optional_protocol_arg} submodule update --init ${optional_recursive_arg} ${optional_depth_arg} "${submodule_path}"
    RESULT_VARIABLE process_exit_code
    WORKING_DIRECTORY "${working_directory}"
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to update the following git submodule: \"${submodule_path}\"")
  endif()

  set(initializeGitSubmodule_IsAlreadyCloned FALSE PARENT_SCOPE)
endfunction()

function(patchSubmoduleSourceCode library_name patches_dir source_dir apply_to_dir)

  # We need to "patch" Thrift by avoiding to copy its tutorial folder,
  # because on Windows it contains a symlink that CMake is not able to copy.
  if(DEFINED PLATFORM_WINDOWS AND "${library_name}" STREQUAL "thrift")
    set(exclude_filter ".*/thrift/src/tutorial/.*")
  endif()

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
      message(FATAL_ERROR "Failed to patch the following git submodule: \"${source_dir}\"")
    endif()
  endforeach()

  get_filename_component(parent_dir "${apply_to_dir}" DIRECTORY)

  file(MAKE_DIRECTORY "${parent_dir}")

  if(exclude_filter)
    file(COPY "${source_dir}" DESTINATION "${parent_dir}" REGEX "${exclude_filter}" EXCLUDE)
  else()
    file(COPY "${source_dir}" DESTINATION "${parent_dir}")
  endif()

  # We need to restore the source code to its original state, pre patch
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" reset --hard HEAD
    RESULT_VARIABLE process_exit_code
    WORKING_DIRECTORY "${source_dir}"
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to git reset the following submodule: \"${source_dir}\"")
  endif()

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
        "${ARGS_NAME}"
        "${directory_path}/patches/${submodule_to_patch}"
        "${directory_path}/${submodule_to_patch}"
        "${patched_source_dir}"
      )
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
