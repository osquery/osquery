# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(dbusMain)
  add_library(thirdparty_dbus
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-address.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-auth.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-bus.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-connection.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-credentials.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-errors.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-keyring.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-marshal-header.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-marshal-byteswap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-marshal-recursive.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-marshal-validate.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-message.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-misc.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-nonce.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-object-tree.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-pending-call.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-resources.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-server-socket.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-server-debug-pipe.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-sha.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-signature.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-syntax.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-timeout.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-threads.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-transport.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-transport-socket.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-watch.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-uuidgen.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-transport-unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-server-unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-dataslot.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-file.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-hash.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-internals.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-list.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-marshal-basic.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-memory.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-mempool.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-string.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-sysdeps.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-pipe.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-file-unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-pipe-unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-sysdeps-unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-sysdeps-pthread.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dbus/dbus-userdb.c"
  )

  target_include_directories(thirdparty_dbus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  target_include_directories(thirdparty_dbus SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  target_compile_definitions(thirdparty_dbus PRIVATE
    DBUS_COMPILATION
    HAVE_CONFIG_H
    _GNU_SOURCE
    DBUS_ENABLE_VERBOSE_MODE
  )

  target_link_libraries(thirdparty_dbus
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_expat
  )
endfunction()

dbusMain()
