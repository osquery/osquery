# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(augeasMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  if(PLATFORM_LINUX)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/config"
    )

  elseif(PLATFORM_WINDOWS)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/config"
    )

  elseif(PLATFORM_MACOS)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/config"
    )
  endif()

  # Use the lexer and parser files built on macOS, since they were generated using
  # the most recent versions of flex/bison
  add_library(thirdparty_augeas
    "${library_root}/src/ast.c"
    "${library_root}/src/augeas.c"
    "${library_root}/src/augrun.c"
    "${library_root}/src/builtin.c"
    "${library_root}/src/errcode.c"
    "${library_root}/src/fa.c"
    "${library_root}/src/get.c"
    "${library_root}/src/hash.c"
    "${library_root}/src/info.c"
    "${library_root}/src/internal.c"
    "${library_root}/src/jmt.c"
    "${library_root}/src/lens.c"
    "${library_root}/src/memory.c"
    "${library_root}/src/pathx.c"
    "${library_root}/src/put.c"
    "${library_root}/src/ref.c"
    "${library_root}/src/regexp.c"
    "${library_root}/src/syntax.c"
    "${library_root}/src/transform.c"
    "${library_root}/src/xml.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/x86_64/code/lexer.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/x86_64/code/parser.c"
  )

  target_include_directories(thirdparty_augeas PRIVATE
    "${library_root}/src"
    "${generated_include_headers_path}"
  )

  target_include_directories(thirdparty_augeas SYSTEM INTERFACE
    "${library_root}/src"
  )

  target_compile_definitions(thirdparty_augeas PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_augeas
    PRIVATE
      thirdparty_c_settings
      thirdparty_gnulib_headers

    PUBLIC
      thirdparty_libxml2
      thirdparty_gnulib_library
  )

  set_property(GLOBAL PROPERTY AUGEAS_LENSES_FOLDER_PATH "${library_root}/lenses")
endfunction()

augeasMain()
