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

  if(DEFINED PLATFORM_POSIX)
    # Host-side tool used to compile the magic database at build time.
    # Not installed; magic.mgc below is its only product.
    #
    # A compiled database is needed because .mgc files are locked to the
    # libmagic version that produced them (VERSIONNO in src/file.h), so the
    # databases shipped by the OS are rejected by the vendored library.
    add_executable(libmagic_file_tool
      ${source_files}
      "${library_root}/src/file.c"
    )

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
      thirdparty_zlib
      thirdparty_lzma
      thirdparty_c_settings
    )

    target_include_directories(libmagic_file_tool PRIVATE
      "${library_root}/src"
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )

    if(DEFINED PLATFORM_LINUX)
      target_include_directories(libmagic_file_tool PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
      )

    elseif(DEFINED PLATFORM_MACOS)
      target_include_directories(libmagic_file_tool PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}"
      )
    endif()

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

    add_custom_command(
      OUTPUT "${libmagic_compiled_db}"
      COMMAND "${CMAKE_COMMAND}" "-DOUT=${CMAKE_BINARY_DIR}/magic.all" -P "${libmagic_concat_script}"
      COMMAND $<TARGET_FILE:libmagic_file_tool> -C -m "${CMAKE_BINARY_DIR}/magic.all"
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
