# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

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

    if(NOT EXISTS "${flex_executable_path}")
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

  importSELinux()

  target_link_libraries(thirdparty_augeas PUBLIC
    thirdparty_libxml2
    thirdparty_selinux
  )

  target_link_libraries(thirdparty_augeas PRIVATE
    thirdparty_c_settings
  )

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

function(importSELinux)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/gnulib/src")

  add_library(thirdparty_selinux
    "${library_root}/lib/getfilecon.c"
    "${library_root}/lib/se-context.c"
    "${library_root}/lib/se-selinux.c"
  )

  target_include_directories(thirdparty_selinux PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}/lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/gnulib"
  )

  target_link_libraries(thirdparty_selinux PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_selinux SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/gnulib"
  )
endfunction()

augeasMain()
