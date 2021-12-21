# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(gnulibMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_gnulib_library
    "${library_root}/lib/asnprintf.c"
    "${library_root}/lib/basename-lgpl.c"
    "${library_root}/lib/dirname-lgpl.c"
    "${library_root}/lib/glthread/lock.c"
    "${library_root}/lib/glthread/threadlib.c"
    "${library_root}/lib/hard-locale.c"
    "${library_root}/lib/localcharset.c"
    "${library_root}/lib/localtime-buffer.c"
    "${library_root}/lib/malloca.c"
    "${library_root}/lib/mbrtowc.c"
    "${library_root}/lib/nl_langinfo.c"
    "${library_root}/lib/printf-args.c"
    "${library_root}/lib/printf-parse.c"
    "${library_root}/lib/regex.c"
    "${library_root}/lib/safe-alloc.c"
    "${library_root}/lib/se-context.c"
    "${library_root}/lib/se-selinux.c"
    "${library_root}/lib/stat-time.c"
    "${library_root}/lib/stripslash.c"
    "${library_root}/lib/strnlen1.c"
    "${library_root}/lib/tempname.c"
    "${library_root}/lib/unistd.c"
    "${library_root}/lib/wctype-h.c"
    "${library_root}/lib/xsize.c"
  )

  if(PLATFORM_LINUX)
    target_sources(thirdparty_gnulib_library PRIVATE
      "${library_root}/lib/vasnprintf.c"
    )

    if(TARGET_PROCESSOR STREQUAL "x86_64")
      target_sources(thirdparty_gnulib_library PRIVATE
        "${library_root}/lib/hash.c"
        "${library_root}/lib/strstr.c"
        "${library_root}/lib/fnmatch.c"
        "${library_root}/lib/getopt1.c"
        "${library_root}/lib/getopt.c"
      )
    endif()

  elseif(PLATFORM_MACOS)
    target_sources(thirdparty_gnulib_library PRIVATE
      "${library_root}/lib/vasnprintf.c"
      "${library_root}/lib/argz.c"
      "${library_root}/lib/canonicalize-lgpl.c"
      "${library_root}/lib/fnmatch.c"
      "${library_root}/lib/getopt.c"
      "${library_root}/lib/getopt1.c"
      "${library_root}/lib/lstat.c"
      "${library_root}/lib/mempcpy.c"
      "${library_root}/lib/rawmemchr.c"
      "${library_root}/lib/readlink.c"
      "${library_root}/lib/stat.c"
      "${library_root}/lib/strchrnul.c"
      "${library_root}/lib/strstr.c"
    )

    if(TARGET_PROCESSOR STREQUAL "aarch64")
      target_sources(thirdparty_gnulib_library PRIVATE
        "${library_root}/lib/getdelim.c"
        "${library_root}/lib/getline.c"
        "${library_root}/lib/gettimeofday.c"
        "${library_root}/lib/memchr.c"
        "${library_root}/lib/mkdir.c"
        "${library_root}/lib/mkstemp.c"
        "${library_root}/lib/stpncpy.c"
      )
    endif()
  endif()

  if(PLATFORM_LINUX)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_WINDOWS)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_MACOS)
    set(generated_include_headers_path
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}"
    )
  endif()

  target_include_directories(thirdparty_gnulib_library PRIVATE
    "${library_root}/lib"
    "${generated_include_headers_path}/lib"
    "${generated_include_headers_path}/config"
  )

  target_compile_definitions(thirdparty_gnulib_library PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_gnulib_library
    PRIVATE
      thirdparty_c_settings
  )

  add_library(thirdparty_gnulib_headers INTERFACE)
  target_include_directories(thirdparty_gnulib_headers SYSTEM INTERFACE
    "${library_root}/lib"
    "${generated_include_headers_path}/lib"
    "${generated_include_headers_path}/config"
  )
endfunction()

gnulibMain()
