# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# This function takes the global properties saved by addOsqueryExtensionEx and 
# generates a single extension executable containing all the user code
function(generateOsqueryExtensionGroup)
  get_property(extension_source_files GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_SOURCES)
  if("${extension_source_files}" STREQUAL "")
    return()
  endif()

  if(DEFINED ENV{OSQUERY_EXTENSION_GROUP_NAME} OR ENV{OSQUERY_EXTENSION_GROUP_VERSION})
    message(WARNING "ENV {OSQUERY_EXTENSION_GROUP_NAME/VERSION} has been deprecated. Please set cache variable!")
  endif()

  set(OSQUERY_EXTENSION_GROUP_NAME "osquery_extension_group" CACHE STRING "Overrides osquery extension group name")

  set(OSQUERY_EXTENSION_GROUP_VERSION "1.0" CACHE STRING "Overrides osquery extension group version")
  
  # Build the include list; this contains the files required to declare
  # the classes used in the REGISTER_EXTERNAL directives
  # Note: The variables in uppercase are used by the template
  get_property(main_include_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_MAIN_INCLUDES)
  foreach(include_file ${main_include_list})
    set(OSQUERY_EXTENSION_GROUP_INCLUDES "${OSQUERY_EXTENSION_GROUP_INCLUDES}\n#include <${include_file}>")
  endforeach()

  # We need to generate the main.cpp file, containing all the required REGISTER_EXTERNAL directives
  get_property(OSQUERY_EXTENSION_GROUP_INITIALIZERS GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_INITIALIZERS)
  configure_file(
    "${CMAKE_SOURCE_DIR}/tools/codegen/templates/osquery_extension_group_main.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/osquery_extension_group_main.cpp"
  )

  # Extensions can no longer control which compilation flags to use here (as they are shared) so
  # we are going to enforce sane defaults
  if(DEFINED PLATFORM_POSIX)
    set(extension_cxx_flags -DBOOST_ASIO_DISABLE_STD_STRING_VIEW)
  else()
    set(extension_cxx_flags /W4)
  endif()

  # Generate the extension target
  add_executable("${OSQUERY_EXTENSION_GROUP_NAME}"
    "${CMAKE_CURRENT_BINARY_DIR}/osquery_extension_group_main.cpp"
    ${extension_source_files}
  )

  set_property(TARGET "${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTY INCLUDE_DIRECTORIES "")
  target_compile_options("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE ${extension_cxx_flags})

  target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE
    external_options
  )
  
  if(DEFINED PLATFORM_LINUX)
    target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE
      thirdparty_libiptc
    )
  endif()

  set_target_properties("${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTIES
    OUTPUT_NAME "${OSQUERY_EXTENSION_GROUP_NAME}.ext"
  )

  get_property(include_folder_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_INCLUDE_FOLDERS)
  if(NOT "${include_folder_list}" STREQUAL "")
    target_include_directories("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE ${include_folder_list})
  endif()

  # Apply the user (extension) settings
  get_property(library_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_LIBRARIES)
  if(NOT "${library_list}" STREQUAL "")
    target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE ${library_list})
  endif()
endfunction()

function(addOsqueryExtensionEx class_name extension_type extension_name ${ARGN})
  # Make sure the extension type is valid
  if(NOT "${extension_type}" STREQUAL "config" AND NOT "${extension_type}" STREQUAL "table")
    message(FATAL_ERROR "Invalid extension type specified")
  endif()

  # Update the initializer list; this will be added to the main.cpp file of the extension group
  set_property(GLOBAL APPEND_STRING PROPERTY
    OSQUERY_EXTENSION_GROUP_INITIALIZERS
    "REGISTER_EXTERNAL(${class_name}, \"${extension_type}\", \"${extension_name}\");\n"
  )

  # Loop through each argument
  foreach(argument ${ARGN})
    if("${argument}" STREQUAL "SOURCES" OR "${argument}" STREQUAL "LIBRARIES" OR
      "${argument}" STREQUAL "INCLUDEDIRS" OR "${argument}" STREQUAL "MAININCLUDES")
      set(current_scope "${argument}")
      continue()
    endif()

    if("${current_scope}" STREQUAL "SOURCES")
      if(NOT IS_ABSOLUTE "${argument}")
        set(argument "${CMAKE_CURRENT_SOURCE_DIR}/${argument}")
      endif()
      list(APPEND source_file_list "${argument}")

    elseif("${current_scope}" STREQUAL "INCLUDEDIRS")
      if(NOT IS_ABSOLUTE "${argument}")
        set(argument "${CMAKE_CURRENT_SOURCE_DIR}/${argument}")
      endif()
      list(APPEND include_folder_list "${argument}")

    elseif("${current_scope}" STREQUAL "LIBRARIES")
      list(APPEND library_list "${argument}")

    elseif("${current_scope}" STREQUAL "MAININCLUDES")
      list(APPEND main_include_list "${argument}")
    else()
      message(FATAL_ERROR "Invalid scope")
    endif()
  endforeach()

  # Validate the arguments
  if("${source_file_list}" STREQUAL "")
    message(FATAL_ERROR "Source files are missing")
  endif()

  if("${main_include_list}" STREQUAL "")
    message(FATAL_ERROR "The main include list is missing")
  endif()

  # Update the global properties
  set_property(GLOBAL APPEND PROPERTY OSQUERY_EXTENSION_GROUP_SOURCES
    ${source_file_list}
  )

  set_property(GLOBAL APPEND PROPERTY OSQUERY_EXTENSION_GROUP_MAIN_INCLUDES
    ${main_include_list}
  )

  if(NOT "${library_list}" STREQUAL "")
    set_property(GLOBAL APPEND PROPERTY OSQUERY_EXTENSION_GROUP_LIBRARIES
      ${library_list}
    )
  endif()

  if(NOT "${include_folder_list}" STREQUAL "")
    set_property(GLOBAL APPEND PROPERTY OSQUERY_EXTENSION_GROUP_INCLUDE_FOLDERS
      ${include_folder_list}
    )
  endif()
endfunction()

function(add_osquery_extension_ex class_name extension_type extension_name ${ARGN})
  message(WARNING "add_osquery_extension_ex has been deprecated. Please use addOsqueryExtensionEx!")
  addOsqueryExtensionEx(${class_name} ${extension_type} ${extension_name} ${ARGN})
endfunction()

function(addOsqueryExtension TARGET)
  add_executable(${TARGET} ${ARGN})
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${TARGET}.ext")
  target_link_libraries(${TARGET} PRIVATE
    external_options
  )
endfunction()