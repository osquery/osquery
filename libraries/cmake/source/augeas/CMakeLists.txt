# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(augeasMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_augeas
    "${library_root}/src/xml.c"
    "${library_root}/src/memory.c"
    "${library_root}/src/lens.c"
    "${library_root}/src/builtin.c"
    "${library_root}/src/ref.c"
    "${library_root}/src/transform.c"
    "${library_root}/src/augeas.c"
    "${library_root}/src/syntax.c"
    "${library_root}/src/augrun.c"
    "${library_root}/src/fa.c"
    "${library_root}/src/internal.c"
    "${library_root}/src/info.c"
    "${library_root}/src/ast.c"
    "${library_root}/src/pathx.c"
    "${library_root}/src/regexp.c"
    "${library_root}/src/errcode.c"
    "${library_root}/src/get.c"
    "${library_root}/src/jmt.c"
    "${library_root}/src/put.c"
    "${library_root}/src/hash.c"
  )

  # Flex and Bison are now required, since they are needed to build augeas.
  # We could generate those files locally and commit them if we don't want
  # to have them as hard dependencies
  if(DEFINED PLATFORM_MACOS)
    # We need to use Bison and Flex from homebrew because the ones provided by
    # Xcode are not compatible
    set(bison_executable_path "/usr/local/opt/bison/bin/bison")
    set(flex_executable_path "/usr/local/opt/flex/bin/flex")

    if(EXISTS "${bison_executable_path}")
      set(BISON_EXECUTABLE "${bison_executable_path}")
    endif()

    if(EXISTS "${flex_executable_path}")
      set(FLEX_EXECUTABLE "${flex_executable_path}")
    endif()

    if(NOT DEFINED BISON_EXECUTABLE OR NOT DEFINED FLEX_EXECUTABLE)
      message(FATAL_ERROR "Both bison and flex are required from homebrew; you can install them with `brew install flex bison`")
    endif()

    set(environment_modifier
      "/usr/local/opt/flex/bin:/usr/local/opt/bison/bin:$ENV{PATH}"
    )

  else()
    foreach(dependency FLEX BISON)
      find_package("${dependency}" REQUIRED)
    endforeach()

    set(environment_modifier
      "$ENV{PATH}"
    )
  endif()

  # Generate the parser
  set(augeas_parser_implementation_name "parser")

  set(augeas_parser_implementation "${CMAKE_CURRENT_BINARY_DIR}/${augeas_parser_implementation_name}.c")
  set(augeas_parser_definition "${library_root}/src/${augeas_parser_implementation_name}.y")

  add_custom_command(
    OUTPUT "${augeas_parser_implementation}"
    COMMAND "${CMAKE_COMMAND}" -E env PATH=${environment_modifier} "${BISON_EXECUTABLE}" "${augeas_parser_definition}" -o "${augeas_parser_implementation}"
    DEPENDS "${augeas_parser_definition}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Bison: Generarating augeas parser"
    VERBATIM
  )

  add_custom_target(
    augeas_parser_implementation_generator
    DEPENDS "${augeas_parser_implementation}"
  )

  # Generate the lexer
  set(augeas_lexer_implementation_name "lexer.c")
  set(augeas_lexer_definition "${library_root}/src/lexer.l")

  set(augeas_lexer_implementation "${CMAKE_CURRENT_BINARY_DIR}/${augeas_lexer_implementation_name}")

  add_custom_command(
    OUTPUT "${augeas_lexer_implementation}"
    COMMAND "${FLEX_EXECUTABLE}" -t "${augeas_lexer_definition}" > "${augeas_lexer_implementation_name}"
    DEPENDS "${augeas_lexer_definition}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Bison: Generarating augeas lexer"
    VERBATIM
  )

  add_custom_target(
    augeas_lexer_implementation_generator
    DEPENDS "${augeas_lexer_implementation}"
  )

  # Set up the dependencies
  add_dependencies(
    augeas_lexer_implementation_generator
    augeas_parser_implementation_generator
  )

  add_dependencies(thirdparty_augeas augeas_lexer_implementation_generator)

  # Add the newly generated files
  target_sources(thirdparty_augeas PRIVATE
    ${augeas_parser_implementation}
    ${augeas_lexer_implementation}
  )

  importGnulibOverrides()

  target_link_libraries(thirdparty_augeas PUBLIC
    thirdparty_libxml2
  )

  target_link_libraries(thirdparty_augeas PRIVATE
    thirdparty_c_settings
    thirdparty_gnulib
  )

  if(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_augeas PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  elseif(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_augeas PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  endif()

  target_include_directories(thirdparty_augeas PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${library_root}/src"
  )

  target_include_directories(thirdparty_augeas SYSTEM INTERFACE
    "${library_root}/src"
  )

  set_property(GLOBAL PROPERTY AUGEAS_LENSES_FOLDER_PATH "${library_root}/lenses")
endfunction()

function(importGnulibOverrides)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/src")

  if(DEFINED PLATFORM_LINUX)
    set(sources
      "${library_root}/lib/getfilecon.c"
      "${library_root}/lib/se-context.c"
      "${library_root}/lib/se-selinux.c"
    )
  elseif(DEFINED PLATFORM_MACOS)
    set(sources
      "${library_root}/lib/setlocale.c"
      "${library_root}/lib/argz.c"
      "${library_root}/lib/canonicalize-lgpl.c"
      "${library_root}/lib/regex.c"
      "${library_root}/lib/fnmatch.c"
      "${library_root}/lib/malloca.c"
      "${library_root}/lib/mempcpy.c"
      "${library_root}/lib/strstr.c"
    )
  endif()

  add_library(thirdparty_gnulib
    ${sources}
  )

  if(DEFINED PLATFORM_MACOS)
    set(public_headers
      "${library_root}/lib/regex.h"
      "${library_root}/lib/canonicalize.h"
      "${library_root}/lib/malloca.h"
    )

    foreach(header ${public_headers})
      get_filename_component(filename "${header}" NAME)

      add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/gnulib/${filename}"
        COMMAND cmake -E copy "${header}" "${CMAKE_CURRENT_BINARY_DIR}/gnulib/${filename}"
      )

      list(APPEND public_headers_output "${CMAKE_CURRENT_BINARY_DIR}/gnulib/${filename}")
    endforeach()

    add_custom_target(thirdparty_gnulib_copy_public_headers DEPENDS ${public_headers_output})
    add_dependencies(thirdparty_gnulib thirdparty_gnulib_copy_public_headers)

    target_include_directories(thirdparty_gnulib PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
      "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/generated/macos"
    )

    target_include_directories(thirdparty_gnulib SYSTEM INTERFACE
      "${CMAKE_CURRENT_BINARY_DIR}/gnulib"
    )

    target_include_directories(thirdparty_gnulib SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/generated/macos"
    )
  elseif(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_gnulib PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
      "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/generated/linux"
    )

    target_include_directories(thirdparty_gnulib SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/generated/linux"
    )
  endif()

  target_include_directories(thirdparty_gnulib PRIVATE
    "${library_root}/lib"
  )

  target_link_libraries(thirdparty_gnulib PRIVATE
    thirdparty_c_settings
  )
endfunction()

augeasMain()
