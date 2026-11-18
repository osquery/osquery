# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libmagicMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(source_files
    "${library_root}/src/buffer.c"
    "${library_root}/src/magic.c"
    "${library_root}/src/apprentice.c"
    "${library_root}/src/softmagic.c"
    "${library_root}/src/ascmagic.c"
    "${library_root}/src/encoding.c"
    "${library_root}/src/compress.c"
    "${library_root}/src/is_csv.c"
    "${library_root}/src/is_json.c"
    "${library_root}/src/is_simh.c"
    "${library_root}/src/is_tar.c"
    "${library_root}/src/readelf.c"
    "${library_root}/src/print.c"
    "${library_root}/src/fsmagic.c"
    "${library_root}/src/funcs.c"
    "${library_root}/src/apptype.c"
    "${library_root}/src/der.c"
    "${library_root}/src/cdf.c"
    "${library_root}/src/cdf_time.c"
    "${library_root}/src/readcdf.c"
  )

  set(compile_definition_list
    HAVE_CONFIG_H
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND compile_definition_list
      MAGIC=\"/usr/local/share/misc/magic\"
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      "${library_root}/src/strlcat.c"
      "${library_root}/src/strlcpy.c"
      "${library_root}/src/fmtcheck.c"
    )
  endif()

  add_library(thirdparty_libmagic ${source_files})
  target_compile_definitions(thirdparty_libmagic PRIVATE
    ${compile_definition_list}
    buffer_init=libmagic_buffer_init
  )

  if(DEFINED PLATFORM_LINUX)
    target_compile_definitions(thirdparty_libmagic PRIVATE
      strlcat=libmagic_strlcat
      strlcpy=libmagic_strlcpy
    )
  endif()

  target_link_libraries(thirdparty_libmagic PUBLIC
    thirdparty_zlib
    thirdparty_lzma
  )

  target_link_libraries(thirdparty_libmagic PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libmagic PRIVATE
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_libmagic PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_libmagic PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}"
    )
  endif()

  target_include_directories(thirdparty_libmagic SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  # The compiled database format version this libmagic loads (VERSIONNO in
  # src/file.h, which is not a public header). The magic table uses it to
  # skip databases compiled by other libmagic versions before loading them.
  file(STRINGS "${library_root}/src/file.h" libmagic_versionno_line
    REGEX "^#define[ \t]+VERSIONNO[ \t]+[0-9]+"
  )

  string(REGEX REPLACE "^#define[ \t]+VERSIONNO[ \t]+([0-9]+).*" "\\1"
    libmagic_db_version "${libmagic_versionno_line}"
  )

  if(NOT libmagic_db_version MATCHES "^[0-9]+$")
    message(FATAL_ERROR "Could not read VERSIONNO from libmagic's src/file.h")
  endif()

  target_compile_definitions(thirdparty_libmagic INTERFACE
    OSQUERY_LIBMAGIC_DB_VERSION=${libmagic_db_version}
  )

  if(DEFINED PLATFORM_POSIX)
    # Tool that compiles the magic database during the build. Not installed;
    # magic.mgc below is its only product.
    #
    # A compiled database is needed because .mgc files are locked to the
    # libmagic version that produced them (VERSIONNO in src/file.h), so the
    # databases shipped by the OS are rejected by the vendored library.
    #
    # The tool runs on the build host. On macOS it is built for the host's
    # architecture, which CMAKE_OSX_ARCHITECTURES may not match. Elsewhere it
    # is built for the target, and a cross-compiled build runs it through
    # CMAKE_CROSSCOMPILING_EMULATOR. Compiling a database decompresses
    # nothing, so the tool is built without compression support and links none
    # of the target's compression libraries. libmagic loads a database written
    # on a host of either byte order.
    if(DEFINED PLATFORM_MACOS)
      if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "arm64")
        set(libmagic_tool_processor "aarch64")
      else()
        set(libmagic_tool_processor "${CMAKE_HOST_SYSTEM_PROCESSOR}")
      endif()

      set(libmagic_tool_config "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${libmagic_tool_processor}/config.h")
    else()
      set(libmagic_tool_config "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}/config.h")
    endif()

    if(NOT EXISTS "${libmagic_tool_config}")
      message(FATAL_ERROR "No libmagic configuration to build libmagic_file_tool with: ${libmagic_tool_config}")
    endif()

    if(CMAKE_CROSSCOMPILING AND NOT CMAKE_CROSSCOMPILING_EMULATOR)
      message(FATAL_ERROR "Cross-compiling needs CMAKE_CROSSCOMPILING_EMULATOR to run libmagic_file_tool, which compiles the magic database")
    endif()

    # The configuration, with compression support turned off. configure_file
    # rewrites the copy only when it changes.
    file(READ "${libmagic_tool_config}" libmagic_tool_config_content)
    foreach(libmagic_compression_macro
      HAVE_ZLIB_H ZLIBSUPPORT
      HAVE_LZMA_H HAVE_LIBLZMA XZLIBSUPPORT
      HAVE_BZLIB_H BZLIBSUPPORT
      HAVE_ZSTD_H HAVE_LIBZSTD ZSTDLIBSUPPORT
      HAVE_LZLIB_H LZLIBSUPPORT
    )
      string(REGEX REPLACE
        "#define ${libmagic_compression_macro} [^\n]*"
        "/* #undef ${libmagic_compression_macro} */"
        libmagic_tool_config_content
        "${libmagic_tool_config_content}"
      )
    endforeach()

    set(libmagic_tool_config_dir "${CMAKE_CURRENT_BINARY_DIR}/libmagic_file_tool_config")
    file(WRITE "${libmagic_tool_config_dir}/config.h.in" "${libmagic_tool_config_content}")
    configure_file(
      "${libmagic_tool_config_dir}/config.h.in"
      "${libmagic_tool_config_dir}/config.h"
      COPYONLY
    )

    add_executable(libmagic_file_tool
      ${source_files}
      "${library_root}/src/file.c"
    )

    if(DEFINED PLATFORM_MACOS)
      set_target_properties(libmagic_file_tool PROPERTIES
        OSX_ARCHITECTURES "${CMAKE_HOST_SYSTEM_PROCESSOR}"
      )
    endif()

    target_compile_definitions(libmagic_file_tool PRIVATE
      ${compile_definition_list}
      buffer_init=libmagic_buffer_init
    )

    if(DEFINED PLATFORM_LINUX)
      target_compile_definitions(libmagic_file_tool PRIVATE
        strlcat=libmagic_strlcat
        strlcpy=libmagic_strlcpy
      )
    endif()

    target_link_libraries(libmagic_file_tool PRIVATE
      thirdparty_c_settings
    )

    target_include_directories(libmagic_file_tool PRIVATE
      "${libmagic_tool_config_dir}"
      "${library_root}/src"
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )

    # Compile a magic database matching the vendored library, from the
    # Magdir rules shipped with it. System databases can't be used instead:
    # libmagic refuses .mgc files compiled by a different version.
    file(GLOB libmagic_magic_fragments "${library_root}/magic/Magdir/*")
    set(libmagic_compiled_db "${CMAKE_BINARY_DIR}/magic.mgc")

    # Helper run with cmake -P to concatenate the fragments. The list is
    # baked into the script at configure time: neither a shell redirect nor
    # a list on the command line works portably inside add_custom_command.
    set(libmagic_concat_script "${CMAKE_CURRENT_BINARY_DIR}/libmagic_concat.cmake")
    set(libmagic_concat_body "set(out \"\")\n")
    foreach(frag ${libmagic_magic_fragments})
      string(APPEND libmagic_concat_body "file(READ \"${frag}\" content)\nstring(APPEND out \"\${content}\")\n")
    endforeach()
    string(APPEND libmagic_concat_body "file(WRITE \"\${OUT}\" \"\${out}\")\n")
    file(WRITE "${libmagic_concat_script}" "${libmagic_concat_body}")

    # The tool is named by its target rather than $<TARGET_FILE:...>, so that
    # a cross-compiled build runs it through CMAKE_CROSSCOMPILING_EMULATOR.
    add_custom_command(
      OUTPUT "${libmagic_compiled_db}"
      COMMAND "${CMAKE_COMMAND}" "-DOUT=${CMAKE_BINARY_DIR}/magic.all" -P "${libmagic_concat_script}"
      COMMAND libmagic_file_tool -C -m "${CMAKE_BINARY_DIR}/magic.all"
      COMMAND "${CMAKE_COMMAND}" -E rename "${CMAKE_BINARY_DIR}/magic.all.mgc" "${libmagic_compiled_db}"
      DEPENDS libmagic_file_tool ${libmagic_magic_fragments}
      COMMENT "Compiling the magic database from the bundled rules"
      # file -C writes the compiled database into the working directory
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    )

    add_custom_target(generate_magic_db ALL
      DEPENDS "${libmagic_compiled_db}"
    )
  endif()
endfunction()

libmagicMain()
