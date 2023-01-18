# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(dbusMain)
  set(library_root "${OSQUERY_dbus_ROOT_DIR}")

  add_library(thirdparty_dbus
    "${library_root}/dbus/dbus-address.c"
    "${library_root}/dbus/dbus-auth.c"
    "${library_root}/dbus/dbus-bus.c"
    "${library_root}/dbus/dbus-connection.c"
    "${library_root}/dbus/dbus-credentials.c"
    "${library_root}/dbus/dbus-errors.c"
    "${library_root}/dbus/dbus-keyring.c"
    "${library_root}/dbus/dbus-marshal-header.c"
    "${library_root}/dbus/dbus-marshal-byteswap.c"
    "${library_root}/dbus/dbus-marshal-recursive.c"
    "${library_root}/dbus/dbus-marshal-validate.c"
    "${library_root}/dbus/dbus-message.c"
    "${library_root}/dbus/dbus-misc.c"
    "${library_root}/dbus/dbus-nonce.c"
    "${library_root}/dbus/dbus-object-tree.c"
    "${library_root}/dbus/dbus-pending-call.c"
    "${library_root}/dbus/dbus-resources.c"
    "${library_root}/dbus/dbus-server.c"
    "${library_root}/dbus/dbus-server-socket.c"
    "${library_root}/dbus/dbus-server-debug-pipe.c"
    "${library_root}/dbus/dbus-sha.c"
    "${library_root}/dbus/dbus-signature.c"
    "${library_root}/dbus/dbus-syntax.c"
    "${library_root}/dbus/dbus-timeout.c"
    "${library_root}/dbus/dbus-threads.c"
    "${library_root}/dbus/dbus-transport.c"
    "${library_root}/dbus/dbus-transport-socket.c"
    "${library_root}/dbus/dbus-watch.c"
    "${library_root}/dbus/dbus-uuidgen.c"
    "${library_root}/dbus/dbus-transport-unix.c"
    "${library_root}/dbus/dbus-server-unix.c"
    "${library_root}/dbus/dbus-dataslot.c"
    "${library_root}/dbus/dbus-file.c"
    "${library_root}/dbus/dbus-hash.c"
    "${library_root}/dbus/dbus-internals.c"
    "${library_root}/dbus/dbus-list.c"
    "${library_root}/dbus/dbus-marshal-basic.c"
    "${library_root}/dbus/dbus-memory.c"
    "${library_root}/dbus/dbus-mempool.c"
    "${library_root}/dbus/dbus-string.c"
    "${library_root}/dbus/dbus-sysdeps.c"
    "${library_root}/dbus/dbus-pipe.c"
    "${library_root}/dbus/dbus-file-unix.c"
    "${library_root}/dbus/dbus-pipe-unix.c"
    "${library_root}/dbus/dbus-sysdeps-unix.c"
    "${library_root}/dbus/dbus-sysdeps-pthread.c"
    "${library_root}/dbus/dbus-userdb.c"
  )

  target_include_directories(thirdparty_dbus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}"
    "${library_root}"
  )

  target_include_directories(thirdparty_dbus SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}"
    "${library_root}"
  )

  target_compile_definitions(thirdparty_dbus PRIVATE
    DBUS_COMPILATION
    HAVE_CONFIG_H
    _GNU_SOURCE
    DBUS_STATIC_BUILD
    DBUS_BUILT_R_DYNAMIC
  )

  target_link_libraries(thirdparty_dbus
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_expat
  )
endfunction()

dbusMain()
