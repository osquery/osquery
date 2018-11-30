# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

# Generates an include namespace; this is sadly required by the Buck-based project and can't be removed
function(generateIncludeNamespace target_name namespace_path mode)
  # Make sure we actually have parameters
  if(${ARGC} EQUAL 0)
    message(SEND_ERROR "No library specified")
    return()
  endif()

  # Validate the mode
  if(NOT "${mode}" STREQUAL "FILE_ONLY" AND NOT "${mode}" STREQUAL "FULL_PATH")
    message(SEND_ERROR "Invalid namespace generation mode")
    return()
  endif()

  # Generate a root target that we'll attach to the user target
  set(index 1)

  while(true)
    set(root_target_name "${target_name}_namespace_generator_${index}")
    if(NOT TARGET "${root_target_name}")
      break()
    endif()

    MATH(EXPR index "${index}+1")
  endwhile()

  add_custom_target("${root_target_name}"
    COMMENT "Generating namespace '${namespace_path}' for target '${target_name}'"
  )

  add_dependencies("${target_name}" "${root_target_name}")

  foreach(relative_source_file_path ${ARGN})
    get_filename_component(source_name "${relative_source_file_path}" NAME)

    if("${mode}" STREQUAL "FILE_ONLY")
      set(output_source_file_path "${CMAKE_CURRENT_BINARY_DIR}/${namespace_path}/${source_name}")
    else()
      set(output_source_file_path "${CMAKE_CURRENT_BINARY_DIR}/${namespace_path}/${relative_source_file_path}")
    endif()

    get_filename_component(parent_folder_path "${output_source_file_path}" DIRECTORY)
    set(absolute_source_file_path "${CMAKE_CURRENT_SOURCE_DIR}/${relative_source_file_path}")

    add_custom_command(
      OUTPUT "${output_source_file_path}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${parent_folder_path}"
      COMMAND "${CMAKE_COMMAND}" -E create_symlink "${absolute_source_file_path}" "${output_source_file_path}"
      VERBATIM
    )

    string(REPLACE "/" "_" file_generator_name "${target_name}_namespaced_${relative_source_file_path}")
    add_custom_target("${file_generator_name}" DEPENDS "${output_source_file_path}")
    add_dependencies("${root_target_name}" "${file_generator_name}")
  endforeach()

  get_target_property(target_type "${target_name}" TYPE)
  if("${target_type}" STREQUAL "INTERFACE_LIBRARY")
    set(mode "INTERFACE")
  else()
    set(mode "PUBLIC")
  endif()

  target_include_directories("${target_name}" ${mode} "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

# Generates the global_c_settings and global_cxx_settings target
function(generateGlobalSettingsTargets)
  if("${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(SEND_ERROR "The CMAKE_BUILD_TYPE variabile is empty! Make sure to include globals.cmake before utilities.cmake!")
    return()
  endif()

  # Common settings
  add_library(global_settings INTERFACE)
  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    target_compile_options(global_settings INTERFACE -gdwarf-2 -g3)
  endif()

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_options(global_settings INTERFACE -O)
    target_compile_definitions(global_settings INTERFACE "DEBUG")
  else()
    target_compile_options(global_settings INTERFACE -Oz)
    target_compile_definitions(global_settings INTERFACE "NDEBUG")
  endif()

  set_target_properties(global_settings PROPERTIES
    INTERFACE_POSITION_INDEPENDENT_CODE ON
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(global_settings INTERFACE --no-undefined)
  endif()

  target_compile_definitions(global_settings INTERFACE
    OSQUERY_VERSION=${OSQUERY_VERSION}
    OSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}
    OSQUERY_BUILD_SDK_VERSION=${OSQUERY_BUILD_SDK_VERSION}
  )

  if(DEFINED PLATFORM_LINUX)
    target_compile_definitions(global_settings INTERFACE
      LINUX=1
      POSIX=1
      OSQUERY_LINUX=1
      OSQUERY_POSIX=1
      OSQUERY_BUILD_PLATFORM=linux
      OSQUERY_BUILD_DISTRO=centos7
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_compile_definitions(global_settings INTERFACE
      APPLE=1
      DARWIN=1
      BSD=1
      POSIX=1
      OSQUERY_POSIX=1
      OSQUERY_BUILD_PLATFORM=darwin
      OSQUERY_BUILD_DISTRO=10.12
    )

  else()
    message(SEND_ERROR "This platform is not yet supported")
  endif()

  add_library(global_c_settings INTERFACE)
  target_link_libraries(global_c_settings INTERFACE global_settings)

  add_library(global_cxx_settings INTERFACE)
  target_link_libraries(global_cxx_settings INTERFACE global_settings)

  # C++ settings
  target_compile_options(global_cxx_settings INTERFACE
    -Qunused-arguments
    -Wno-shadow-field
    -Wall
    -Wextra
    -Wno-unused-local-typedef
    -Wno-deprecated-register
    -Wno-unknown-warning-option
    -Wstrict-aliasing
    -Wno-missing-field-initializers
    -Wnon-virtual-dtor
    -Wchar-subscripts
    -Wpointer-arith
    -Woverloaded-virtual
    -Wformat
    -Wformat-security
    -Werror=format-security
    -Wuseless-cast
    -Wno-c++11-extensions
    -Wno-zero-length-array
    -Wno-unused-parameter
    -Wno-gnu-case-range
    -Weffc++
    -fpermissive
    -fstack-protector-all
    -fdata-sections
    -ffunction-sections
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -fno-limit-debug-info
    -pipe
    -pedantic
    -stdlib=libc++
  )

  if(DEFINED PLATFORM_LINUX)
    target_compile_options(global_cxx_settings INTERFACE
      -stdlib=libc++
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_compile_options(global_cxx_settings INTERFACE
      -x objective-c++
      -fobjc-arc
    )

  endif()

  target_compile_features(global_cxx_settings INTERFACE cxx_std_14)

  target_link_libraries(global_cxx_settings INTERFACE c++ c++abi)

  # C settings
  target_compile_options(global_c_settings INTERFACE
    -std=gnu11
    -Qunused-arguments
    -Wno-shadow-field
    -Wall
    -Wextra
    -Wno-unused-local-typedef
    -Wno-deprecated-register
    -Wno-unknown-warning-option
    -Wstrict-aliasing
    -Wno-missing-field-initializers
    -Wnon-virtual-dtor
    -Wchar-subscripts
    -Wpointer-arith
    -Woverloaded-virtual
    -Wformat
    -Wformat-security
    -Werror=format-security
    -Wuseless-cast
    -Wno-c99-extensions
    -Wno-zero-length-array
    -Wno-unused-parameter
    -Wno-gnu-case-range
    -Weffc++
    -fpermissive
    -fstack-protector-all
    -fdata-sections
    -ffunction-sections
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -fno-limit-debug-info
    -pipe
    -pedantic
  )
endfunction()

# Marks the specified target to enable link whole archive
function(enableLinkWholeArchive target_name)
  if(NOT TARGET "${target_name}")
    message(SEND_ERROR "The specified target does not exists")
    return()
  endif()

  set_property(GLOBAL APPEND PROPERTY "LinkWholeArchive_targetList" "${target_name}")
endfunction()

# Returns a list containing all the targets that have been created
function(getTargetList)
  set(new_directory_queue "${CMAKE_SOURCE_DIR}")

  while(true)
    set(directory_queue ${new_directory_queue})
    unset(new_directory_queue)

    foreach(directory ${directory_queue})
      get_property(child_directories DIRECTORY "${directory}" PROPERTY "SUBDIRECTORIES")
      list(APPEND visited_directories "${directory}")

      list(APPEND new_directory_queue ${child_directories})
    endforeach()

    list(LENGTH new_directory_queue new_directory_queue_size)
    if(${new_directory_queue_size} EQUAL 0)
      break()
    endif()
  endwhile()

  foreach(directory ${visited_directories})
    get_property(directory_target_list DIRECTORY "${directory}" PROPERTY "BUILDSYSTEM_TARGETS")
    list(APPEND target_list ${directory_target_list})
  endforeach()

  set(getTargetList_output ${target_list} PARENT_SCOPE)
endfunction()

# Copies the interface include directories from one target to the other
function(inheritIncludeDirectoriesFromSingleTarget destination_target source_target)
  if(NOT TARGET "${destination_target}" OR NOT TARGET "${source_target}")
    message(SEND_ERROR "Invalid argument(s) specified")
    return()
  endif()

  get_target_property(destination_target_type "${destination_target}" TYPE)
  if("${destination_target_type}" STREQUAL "INTERFACE_LIBRARY")
    set(mode "INTERFACE")
  else()
    set(mode "PUBLIC")
  endif()

  get_target_property(src_interface_include_dirs "${source_target}" "INTERFACE_INCLUDE_DIRECTORIES")
  if(NOT "${src_interface_include_dirs}" STREQUAL "src_interface_include_dirs-NOTFOUND")
    target_include_directories("${destination_target}" ${mode} ${src_interface_include_dirs})
  endif()
endfunction()

# Copies the interface compile definitions from one target to the other
function(inheritCompileDefinitionsFromSingleTarget destination_target source_target)
  if(NOT TARGET "${destination_target}" OR NOT TARGET "${source_target}")
    message(SEND_ERROR "Invalid argument(s) specified")
    return()
  endif()

  get_target_property(destination_target_type "${destination_target}" TYPE)
  if("${destination_target_type}" STREQUAL "INTERFACE_LIBRARY")
    set(mode "INTERFACE")
  else()
    set(mode "PUBLIC")
  endif()

  get_target_property(src_interface_compile_defs "${source_target}" "INTERFACE_COMPILE_DEFINITIONS")
  if(NOT "${src_interface_compile_defs}" STREQUAL "src_interface_compile_defs-NOTFOUND")
    target_compile_definitions("${destination_target}" ${mode} ${src_interface_compile_defs})
  endif()
endfunction()

# Returns true if the specified target should be linked with --whole-archive
function(isWholeLinkLibraryTarget target_name)
  get_property(LinkWholeArchive_targetList GLOBAL PROPERTY "LinkWholeArchive_targetList")

  list(FIND LinkWholeArchive_targetList "${target_name}" index)
  if(${index} EQUAL -1)
    set(isWholeLinkLibraryTarget_output false PARENT_SCOPE)
  else()
    set(isWholeLinkLibraryTarget_output true PARENT_SCOPE)
  endif()
endfunction()

# Processes every target created inside the project, applying the link whole archive settings
function(processLinkWholeArchiveSettings)
  # Do not do anything if we building shared libs
  if(${BUILD_SHARED_LIBS})
    message(STATUS "Skipping link_whole handling (building shared libraries)")
    return()
  endif()

  message(STATUS "Processing link_whole settings...")

  # Enumerate all the targets we have in the project and all the targets we need to link with --whole-archive
  getTargetList()

  foreach(project_target ${getTargetList_output})
    get_target_property(project_target_type "${project_target}" TYPE)
    if("${project_target_type}" STREQUAL "UTILITY")
      continue()
    endif()

    list(APPEND project_target_list "${project_target}")
  endforeach()

  # Iterate through each target and its dependencies and do the substitution
  while(true)
    set(substitution_performed false)

    foreach(project_target ${project_target_list})
      get_target_property(project_target_type "${project_target}" TYPE)

      set(link_lib_property_list "INTERFACE_LINK_LIBRARIES")
      if(NOT "${project_target_type}" STREQUAL "INTERFACE_LIBRARY")
        list(APPEND link_lib_property_list "LINK_LIBRARIES")
      endif()

      foreach(link_lib_property ${link_lib_property_list})
        unset(new_project_target_dependency_list)
        unset(dependency_to_migrate_list)

        get_target_property(project_target_dependency_list "${project_target}" "${link_lib_property}")
        if("${project_target_dependency_list}" STREQUAL "project_target_dependency_list-NOTFOUND")
          continue()
        endif()

        list(REMOVE_DUPLICATES project_target_dependency_list)

        foreach(project_target_dependency ${project_target_dependency_list})
          isWholeLinkLibraryTarget("${project_target_dependency}")
          if(NOT ${isWholeLinkLibraryTarget_output})
            list(APPEND new_project_target_dependency_list "${project_target_dependency}")
            continue()
          endif()

          if(DEFINED PLATFORM_LINUX)
            list(APPEND new_project_target_dependency_list
              "-Wl,--whole-archive $<TARGET_FILE:${project_target_dependency}> -Wl,--no-whole-archive"
            )
          elseif(DEFINED PLATFORM_MACOS)
            list(APPEND new_project_target_dependency_list
              "-Wl,-force_load $<TARGET_FILE:${project_target_dependency}>"
            )
          endif()

          add_dependencies("${project_target}" "${project_target_dependency}")

          list(APPEND dependency_to_migrate_list "${project_target_dependency}")
          set(substitution_performed true)
        endforeach()

        foreach(dependency_to_migrate ${dependency_to_migrate_list})
          inheritIncludeDirectoriesFromSingleTarget("${project_target}" "${dependency_to_migrate}")
          inheritCompileDefinitionsFromSingleTarget("${project_target}" "${dependency_to_migrate}")

          get_target_property(additional_dependencies "${dependency_to_migrate}" INTERFACE_LINK_LIBRARIES)
          if(NOT "${additional_dependencies}" STREQUAL "additional_dependencies-NOTFOUND")
            list(APPEND new_project_target_dependency_list ${additional_dependencies})
          endif()
        endforeach()

        list(REMOVE_DUPLICATES new_project_target_dependency_list)
        set_target_properties("${project_target}" PROPERTIES "${link_lib_property}" "${new_project_target_dependency_list}")
      endforeach()
    endforeach()

    if(NOT ${substitution_performed})
      break()
    endif()
  endwhile()

  message(STATUS "Finished processing link_whole settings")
endfunction()
