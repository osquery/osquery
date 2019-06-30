# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

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
    set(root_target_name "${target_name}_ns_gen_${index}")
    if(NOT TARGET "${root_target_name}")
      break()
    endif()

    MATH(EXPR index "${index}+1")
  endwhile()

  add_custom_target("${root_target_name}"
    COMMENT "Generating namespace '${namespace_path}' for target '${target_name}'"
  )

  add_dependencies("${target_name}" "${root_target_name}")

  get_target_property(target_type "${target_name}" TYPE)
  if("${target_type}" STREQUAL "INTERFACE_LIBRARY")
    set(target_mode "INTERFACE")
  else()
    set(target_mode "PUBLIC")
  endif()

  foreach(relative_source_file_path ${ARGN})
    get_filename_component(source_name "${relative_source_file_path}" NAME)

    set(target_namespace_root_directory "${CMAKE_BINARY_DIR}/ns_${target_name}")

    if("${mode}" STREQUAL "FILE_ONLY")
      set(output_source_file_path "${target_namespace_root_directory}/${namespace_path}/${source_name}")
    else()
      set(output_source_file_path "${target_namespace_root_directory}/${namespace_path}/${relative_source_file_path}")
    endif()

    get_filename_component(parent_folder_path "${output_source_file_path}" DIRECTORY)
    set(source_base_path "${CMAKE_CURRENT_SOURCE_DIR}")
    set(absolute_source_file_path "${source_base_path}/${relative_source_file_path}")

    add_custom_command(
      OUTPUT "${output_source_file_path}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${parent_folder_path}"
      COMMAND "${CMAKE_COMMAND}" -E create_symlink "${absolute_source_file_path}" "${output_source_file_path}"
      VERBATIM
    )

    string(REPLACE "/" "_" file_generator_name "${target_name}_ns_${relative_source_file_path}")
    add_custom_target("${file_generator_name}" DEPENDS "${output_source_file_path}")
    add_dependencies("${root_target_name}" "${file_generator_name}")

    if(ADD_HEADERS_AS_SOURCES)
      target_sources("${target_name}" ${target_mode} "${absolute_source_file_path}")
    endif()
  endforeach()

  # So that the IDE finds all the necessary headers
  add_dependencies("prepare_for_ide" "${root_target_name}")

  target_include_directories("${target_name}" ${target_mode} "${target_namespace_root_directory}")
endfunction()

# Generates the global_c_settings, global_cxx_settings targets and the respective thirdparty variant
function(generateGlobalSettingsTargets)

  if(NOT DEFINED PLATFORM_WINDOWS)
    if("${CMAKE_BUILD_TYPE}" STREQUAL "")
      message(SEND_ERROR "The CMAKE_BUILD_TYPE variabile is empty! Make sure to include globals.cmake before utilities.cmake!")
      return()
    endif()
  endif()

  # Common settings
  add_library(global_settings INTERFACE)

  if(DEFINED PLATFORM_WINDOWS)
    target_compile_options(global_settings INTERFACE
      "$<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:/Z7;/Gs;/GS>"
    )

    target_compile_options(global_settings INTERFACE
      "$<$<CONFIG:Debug>:/Od;/UNDEBUG>$<$<NOT:$<CONFIG:Debug>>:/Ot>"
    )
    target_compile_definitions(global_settings INTERFACE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")

    target_link_options(global_settings INTERFACE
      /SUBSYSTEM:CONSOLE
      /LTCG
      ntdll.lib
      ole32.lib
      oleaut32.lib
      ws2_32.lib
      iphlpapi.lib
      netapi32.lib
      rpcrt4.lib
      shlwapi.lib
      version.lib
      wtsapi32.lib
      wbemuuid.lib
      secur32.lib
      taskschd.lib
      dbghelp.lib
      dbgeng.lib
      bcrypt.lib
      crypt32.lib
      wintrust.lib
      setupapi.lib
      advapi32.lib
      userenv.lib
      wevtapi.lib
      shell32.lib
      gdi32.lib
    )
  else()
    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
      target_compile_options(global_settings INTERFACE -gdwarf-2 -g3)
    endif()

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
      target_compile_options(global_settings INTERFACE -O0)
    else()
      target_compile_options(global_settings INTERFACE -Oz)
      target_compile_definitions(global_settings INTERFACE "NDEBUG")
    endif()
  endif()

  set_target_properties(global_settings PROPERTIES
    INTERFACE_POSITION_INDEPENDENT_CODE ON
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_options(global_settings INTERFACE --no-undefined)
  endif()

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
  elseif(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(global_settings INTERFACE
      WIN32=1
      WINDOWS=1
      OSQUERY_WINDOWS=1
      OSQUERY_BUILD_PLATFORM=windows
      OSQUERY_BUILD_DISTRO=10
      BOOST_ALL_NO_LIB
      BOOST_ALL_STATIC_LINK
      _WIN32_WINNT=_WIN32_WINNT_WIN7
      NTDDI_VERSION=NTDDI_WIN7
    )
  else()
    message(FATAL_ERROR "This platform is not yet supported")
  endif()

  add_library(c_settings INTERFACE)
  add_library(cxx_settings INTERFACE)

  # C++ settings
  if(DEFINED PLATFORM_WINDOWS)
    target_compile_options(cxx_settings INTERFACE
      /MT
      /EHs
      /W3
      /guard:cf
      /bigobj
      /Zc:inline-
    )
  else()
    target_compile_options(cxx_settings INTERFACE
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

    target_link_options(cxx_settings INTERFACE
      -stdlib=libc++
    )

    if(DEFINED PLATFORM_MACOS)
      target_compile_options(cxx_settings INTERFACE
        -x objective-c++
        -fobjc-arc
        -Wabi-tag
      )

      target_link_options(cxx_settings INTERFACE
        "SHELL:-framework AppKit"
        "SHELL:-framework Foundation"
        "SHELL:-framework CoreServices"
        "SHELL:-framework CoreFoundation"
        "SHELL:-framework CoreWLAN"
        "SHELL:-framework CoreGraphics"
        "SHELL:-framework DiskArbitration"
        "SHELL:-framework IOKit"
        "SHELL:-framework OpenDirectory"
        "SHELL:-framework Security"
        "SHELL:-framework ServiceManagement"
        "SHELL:-framework SystemConfiguration"
      )

      target_link_libraries(cxx_settings INTERFACE
        iconv
        cups
        bsm
        xar
      )
    endif()

    target_link_libraries(cxx_settings INTERFACE c++ c++abi)
  endif()

  target_compile_features(cxx_settings INTERFACE cxx_std_14)

  # C settings
  if(DEFINED PLATFORM_WINDOWS)
    target_compile_options(c_settings INTERFACE
      /std:c11
      /MT
      /EHs
      /W3
      /guard:cf
      /bigobj
    )
  else()
    target_compile_options(c_settings INTERFACE
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
  endif()

  add_library(global_c_settings INTERFACE)
  target_link_libraries(global_c_settings INTERFACE c_settings global_settings)

  add_library(global_cxx_settings INTERFACE)
  target_link_libraries(global_cxx_settings INTERFACE cxx_settings global_settings)

endfunction()

# Marks the specified target to enable link whole archive
function(enableLinkWholeArchive target_name)
  if(DEFINED PLATFORM_LINUX)
    set(new_project_target_link_options
      "SHELL:-Wl,--whole-archive $<TARGET_FILE:${target_name}> -Wl,--no-whole-archive"
    )
  elseif(DEFINED PLATFORM_MACOS)
    set(new_project_target_link_options
      "SHELL:-Wl,-force_load $<TARGET_FILE:${target_name}>"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    set(new_project_target_link_options
      "/WHOLEARCHIVE:$<TARGET_FILE:${target_name}>"
    )
  endif()

  target_link_options(${target_name} INTERFACE ${new_project_target_link_options})
endfunction()

function(findPythonExecutablePath)
  find_package(Python2 COMPONENTS Interpreter REQUIRED)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)

  set(EX_TOOL_PYTHON2_EXECUTABLE_PATH "${Python2_EXECUTABLE}" PARENT_SCOPE)
  set(EX_TOOL_PYTHON3_EXECUTABLE_PATH "${Python3_EXECUTABLE}" PARENT_SCOPE)
endfunction()

function(generateBuildTimeSourceFile file_path content)
  add_custom_command(
    OUTPUT "${file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo "${content}" > "${file_path}"
    VERBATIM
  )
endfunction()

function(generateUnsupportedPlatformSourceFile)
  set(source_file "${CMAKE_CURRENT_BINARY_DIR}/osquery_unsupported_platform_target_source_file.cpp")
  set(file_content "#error This target does not support this platform")

  generateBuildTimeSourceFile(${source_file} ${file_content})

  set(unsupported_platform_source_file "${source_file}" PARENT_SCOPE)
endfunction()

function(generateCopyFileTarget name type relative_file_paths destination)

  set(source_base_path "${CMAKE_CURRENT_SOURCE_DIR}")

  if(type STREQUAL "REGEX")
    file(GLOB_RECURSE relative_file_paths RELATIVE "${source_base_path}" "${source_base_path}/${relative_file_paths}")
  endif()

  add_library("${name}" INTERFACE)

  foreach(file ${relative_file_paths})
    get_filename_component(intermediate_directory "${file}" DIRECTORY)
    list(APPEND intermediate_directories "${intermediate_directory}")
  endforeach()

  list(REMOVE_DUPLICATES intermediate_directories)

  foreach(directory ${intermediate_directories})
    add_custom_command(
      OUTPUT "${destination}/${directory}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${destination}/${directory}"
    )
    list(APPEND created_directories "${destination}/${directory}")
  endforeach()

  add_custom_target("${name}_create_dirs" DEPENDS "${created_directories}")

  foreach(file ${relative_file_paths})

    get_filename_component(filename "${file}" NAME)

    if("${filename}" STREQUAL "BUCK")
      continue()
    endif()

    add_custom_command(
      OUTPUT "${destination}/${file}"
      COMMAND "${CMAKE_COMMAND}" -E copy "${source_base_path}/${file}" "${destination}/${file}"
    )
    list(APPEND copied_files "${destination}/${file}")
  endforeach()

  add_custom_target("${name}_copy_files" DEPENDS "${name}_create_dirs" "${copied_files}")

  add_dependencies("${name}" "${name}_copy_files")

  set_target_properties("${name}" PROPERTIES INTERFACE_BINARY_DIR "${destination}")

endfunction()

function(add_osquery_executable)
  set(osquery_exe_options EXCLUDE_FROM_ALL;WIN32;MACOSX_BUNDLE)
  set(osquery_exe_ARGN ${ARGN})

  list(GET osquery_exe_ARGN 0 osquery_exe_name)
  list(REMOVE_AT osquery_exe_ARGN 0)

  foreach(arg ${osquery_exe_ARGN})
    list(FIND osquery_exe_options "${arg}" arg_POS)
    if(${arg_POS} EQUAL -1 AND NOT IS_ABSOLUTE "${arg}")
      set(base_path "${CMAKE_CURRENT_SOURCE_DIR}")
      list(APPEND osquery_exe_args "${base_path}/${arg}")
    else()
      list(APPEND osquery_exe_args "${arg}")
    endif()
  endforeach()

  add_executable(${osquery_exe_name} ${osquery_exe_args})

  if("${osquery_exe_name}" MATCHES "-test$" AND DEFINED PLATFORM_POSIX)
    target_link_options("${osquery_exe_name}" PRIVATE -Wno-sign-compare)
  endif()
endfunction()

function(add_osquery_library)
  set(osquery_lib_options STATIC;SHARED;MODULE;OBJECT;UNKNOWN;EXCLUDE_FROM_ALL;IMPORTED;GLOBAL;INTERFACE)
  set(osquery_lib_ARGN ${ARGN})

  list(GET osquery_lib_ARGN 0 osquery_lib_name)
  list(REMOVE_AT osquery_lib_ARGN 0)

  foreach(arg ${osquery_lib_ARGN})
    list(FIND osquery_lib_options "${arg}" arg_POS)
    if(${arg_POS} EQUAL -1 AND NOT IS_ABSOLUTE "${arg}")
      set(base_path "${CMAKE_CURRENT_SOURCE_DIR}")
      list(APPEND osquery_lib_args "${base_path}/${arg}")
    else()
      list(APPEND osquery_lib_args "${arg}")
    endif()
  endforeach()

  add_library(${osquery_lib_name} ${osquery_lib_args})
endfunction()

# This function modifies an existing cache variable but without changing its description
function(overwrite_cache_variable variable_name value)
  get_property(current_help_string CACHE "${variable_name}" PROPERTY HELPSTRING)
  set("${variable_name}" "${value}" CACHE STRING "${current_help_string}" FORCE)
endfunction()

function(generateSpecialTargets)
  # Used to generate all the files necessary to have a complete view of the project in the IDE
  add_custom_target(prepare_for_ide)

  add_custom_target(format_check
    COMMAND ${EX_TOOL_PYTHON2_EXECUTABLE_PATH} ${CMAKE_SOURCE_DIR}/tools/formatting/format-check.py origin/master
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VERBATIM
  )
  add_custom_target(format
    COMMAND ${EX_TOOL_PYTHON2_EXECUTABLE_PATH} ${CMAKE_SOURCE_DIR}/tools/formatting/git-clang-format.py -f --style=file
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VERBATIM)
endfunction()
