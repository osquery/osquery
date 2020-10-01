# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(lldpdMain)
  generateLibevent()
  generateLiblldpd()
endfunction()

function(generateLibevent)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libevent")

  set(sources
    "${library_root}/event.c"
    "${library_root}/evthread.c"
    "${library_root}/buffer.c"
    "${library_root}/bufferevent_sock.c"
    "${library_root}/bufferevent.c"
    "${library_root}/bufferevent_filter.c"
    "${library_root}/bufferevent_pair.c"
    "${library_root}/listener.c"
    "${library_root}/bufferevent_ratelim.c"
    "${library_root}/log.c"
    "${library_root}/evmap.c"
    "${library_root}/evutil.c"
    "${library_root}/evutil_rand.c"
    "${library_root}/select.c"
    "${library_root}/strlcpy.c"
    "${library_root}/poll.c"
    "${library_root}/signal.c"
    "${library_root}/event_tagging.c"
    "${library_root}/evdns.c"
    "${library_root}/http.c"
    "${library_root}/evrpc.c"
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND sources
      "${library_root}/epoll.c"
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND sources
      "${library_root}/kqueue.c"
    )
  endif()

  add_library(thirdparty_libevent
    ${sources}
  )

  target_compile_definitions(thirdparty_libevent PRIVATE
    _FORTIFY_SOURCE=2
    _GNU_SOURCE
  )

  target_link_libraries(thirdparty_libevent PUBLIC
    thirdparty_zlib
  )

  target_link_libraries(thirdparty_libevent PRIVATE
    thirdparty_c_settings
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_libevent PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux/libevent"
    )
    target_include_directories(thirdparty_libevent SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux/libevent"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_libevent PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos/libevent"
    )
    target_include_directories(thirdparty_libevent SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos/libevent"
    )
  endif()

  target_include_directories(thirdparty_libevent PRIVATE
    "${library_root}"
    "${library_root}/include"
    "${library_root}/compat"
  )

  target_include_directories(thirdparty_libevent SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

function(generateLiblldpd)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/src")

  set(sources
    "${library_root}/compat/empty.c"
    "${library_root}/compat/strtonum.c"
    "${library_root}/log.c"
    "${library_root}/version.c"
    "${library_root}/marshal.c"
    "${library_root}/ctl.c"
    "${library_root}/lib/atom.c"
    "${library_root}/lib/connection.c"
    "${library_root}/lib/helpers.c"
    "${library_root}/lib/errors.c"
    "${library_root}/lib/fixedpoint.c"
    "${library_root}/lldpd-structs.c"
    "${library_root}/lib/atoms/dot3.c"
    "${library_root}/lib/atoms/dot1.c"
    "${library_root}/lib/atoms/config.c"
    "${library_root}/lib/atoms/interface.c"
    "${library_root}/lib/atoms/med.c"
    "${library_root}/lib/atoms/port.c"
    "${library_root}/lib/atoms/mgmt.c"
    "${library_root}/lib/atoms/custom.c"
    "${library_root}/lib/atoms/chassis.c"
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND sources
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/src/lib/atom-glue.c"
      "${library_root}/compat/strlcpy.c"
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND sources
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/src/lib/atom-glue.c"
    )
  endif()

  add_library(thirdparty_lldpd
   ${sources}
  )

  target_compile_definitions(thirdparty_lldpd PRIVATE
    _FORTIFY_SOURCE=2
    _GNU_SOURCE
    HAVE_CONFIG_H
    SYSCONFDIR=\"/usr/local/etc\"
    PIC
  )

  target_link_libraries(thirdparty_lldpd PUBLIC
    thirdparty_libevent
  )

  target_link_libraries(thirdparty_lldpd PRIVATE
    thirdparty_c_settings
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_lldpd PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux/liblldpd"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_lldpd PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos/liblldpd"
    )
  endif()

  target_include_directories(thirdparty_lldpd PRIVATE
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${library_root}/lib"
  )

  set(public_header_list
    lldp-const.h
    lib/lldpctl.h
  )

  configure_file(
    "${library_root}/lldp-const.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/lldp-const.h"
    COPYONLY
  )

  configure_file(
    "${library_root}/lib/lldpctl.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/lldpctl.h"
    COPYONLY
  )

  target_include_directories(thirdparty_lldpd SYSTEM INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/include"
  )
endfunction()

lldpdMain()
