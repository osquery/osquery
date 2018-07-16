/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/core.h>
#include <osquery/logger.h>

/*
  systemd build options for creating a static library are not working, so we
  have to import it dynamically!

  The following declarations are based on systemd 229 from Ubuntu 16.04. The
  interface we are using is the most compatible one both with previous
  (Ubuntu 14.04 or CentOS 7) and next versions.

  You can find the original declarations inside the libsystemd-dev files:
   - systemd/sd-bus.h
   - systemd/sd-daemon.h
   - systemd/sd-login.h

  If you want to link against the system library, you can just delete this file.
*/

#include <dlfcn.h>

namespace systemd_deps {
// clang-format off
#define SD_BUS_ERROR_NULL {}
// clang-format on

enum {
  _SD_BUS_TYPE_INVALID = 0,
  SD_BUS_TYPE_BYTE = 'y',
  SD_BUS_TYPE_BOOLEAN = 'b',
  SD_BUS_TYPE_INT16 = 'n',
  SD_BUS_TYPE_UINT16 = 'q',
  SD_BUS_TYPE_INT32 = 'i',
  SD_BUS_TYPE_UINT32 = 'u',
  SD_BUS_TYPE_INT64 = 'x',
  SD_BUS_TYPE_UINT64 = 't',
  SD_BUS_TYPE_DOUBLE = 'd',
  SD_BUS_TYPE_STRING = 's',
  SD_BUS_TYPE_OBJECT_PATH = 'o',
  SD_BUS_TYPE_SIGNATURE = 'g',
  SD_BUS_TYPE_UNIX_FD = 'h',
  SD_BUS_TYPE_ARRAY = 'a',
  SD_BUS_TYPE_VARIANT = 'v',
  SD_BUS_TYPE_STRUCT = 'r',
  SD_BUS_TYPE_STRUCT_BEGIN = '(',
  SD_BUS_TYPE_STRUCT_END = ')',
  SD_BUS_TYPE_DICT_ENTRY = 'e',
  SD_BUS_TYPE_DICT_ENTRY_BEGIN = '{',
  SD_BUS_TYPE_DICT_ENTRY_END = '}',
};

using sd_bus = void*;
struct sd_bus_message;

typedef struct {
  const char* name;
  const char* message;
  int _need_free;
} sd_bus_error;

// clang-format off
using sd_bus_default_system_ptr = int (*)(sd_bus** ret);
using sd_bus_new_ptr = int (*)(sd_bus** ret);
using sd_bus_start_ptr = int (*)(sd_bus* ret);
using sd_bus_get_fd_ptr = int (*)(sd_bus* bus);
using sd_bus_flush_close_unref_ptr = sd_bus* (*)(sd_bus* bus);
using sd_bus_set_address_ptr = int (*)(sd_bus* bus, const char* address);
using sd_bus_message_append_strv_ptr = int (*)(sd_bus_message* m, char** l);
using sd_bus_message_exit_container_ptr = int (*)(sd_bus_message* m);
using sd_bus_message_skip_ptr = int (*)(sd_bus_message* m, const char* types);
using sd_bus_message_unref_ptr = sd_bus_message* (*)(sd_bus_message* m);
using sd_bus_set_allow_interactive_authorization_ptr = int (*)(sd_bus* bus, int b);
using sd_bus_message_read_ptr = int (*)(sd_bus_message* m, const char* types, ...);
using sd_bus_message_read_basic_ptr = int (*)(sd_bus_message* m, char type, void* p);
using sd_bus_message_peek_type_ptr = int (*)(sd_bus_message* m, char* type, const char** contents);
using sd_bus_message_new_method_call_ptr = int (*)(sd_bus* bus, sd_bus_message** m, const char* destination, const char* path, const char* interface, const char* member);
using sd_bus_call_ptr = int (*)(sd_bus* bus, sd_bus_message* m, uint64_t usec, sd_bus_error* ret_error, sd_bus_message** reply);
using sd_bus_call_method_ptr = int (*)(sd_bus* bus, const char* destination, const char* path, const char* interface, const char* member, sd_bus_error* ret_error, sd_bus_message** reply, const char* types, ...);
using sd_bus_message_enter_container_ptr = int (*)(sd_bus_message* m, char type, const char* contents);

sd_bus_default_system_ptr sd_bus_default_system = nullptr;
sd_bus_new_ptr sd_bus_new = nullptr;
sd_bus_start_ptr sd_bus_start = nullptr;
sd_bus_get_fd_ptr sd_bus_get_fd = nullptr;
sd_bus_flush_close_unref_ptr sd_bus_flush_close_unref = nullptr;
sd_bus_set_address_ptr sd_bus_set_address = nullptr;
sd_bus_message_append_strv_ptr sd_bus_message_append_strv = nullptr;
sd_bus_message_read_ptr sd_bus_message_read = nullptr;
sd_bus_message_read_basic_ptr sd_bus_message_read_basic = nullptr;
sd_bus_message_exit_container_ptr sd_bus_message_exit_container = nullptr;
sd_bus_message_skip_ptr sd_bus_message_skip = nullptr;
sd_bus_message_unref_ptr sd_bus_message_unref = nullptr;
sd_bus_message_peek_type_ptr sd_bus_message_peek_type = nullptr;
sd_bus_message_new_method_call_ptr sd_bus_message_new_method_call = nullptr;
sd_bus_call_ptr sd_bus_call = nullptr;
sd_bus_call_method_ptr sd_bus_call_method = nullptr;
sd_bus_message_enter_container_ptr sd_bus_message_enter_container = nullptr;
sd_bus_set_allow_interactive_authorization_ptr sd_bus_set_allow_interactive_authorization = nullptr;
// clang-format on

bool loadSystemdDependencies() {
  auto library_list = {"libsystemd.so", "libsystemd.so.0"};

  void* systemd_library = nullptr;
  for (const auto& library_name : library_list) {
    systemd_library = dlopen(library_name, RTLD_NOW | RTLD_GLOBAL);
    if (systemd_library != nullptr) {
      break;
    }
  }

  if (systemd_library == nullptr) {
    VLOG(1) << "systemd not found";
    return false;
  }

  // clang-format off
  sd_bus_default_system = reinterpret_cast<sd_bus_default_system_ptr>(dlsym(systemd_library, "sd_bus_default_system"));
  sd_bus_set_allow_interactive_authorization = reinterpret_cast<sd_bus_set_allow_interactive_authorization_ptr>(dlsym(systemd_library, "sd_bus_set_allow_interactive_authorization"));
  sd_bus_new = reinterpret_cast<sd_bus_new_ptr>(dlsym(systemd_library, "sd_bus_new"));
  sd_bus_start = reinterpret_cast<sd_bus_start_ptr>(dlsym(systemd_library, "sd_bus_start"));
  sd_bus_get_fd = reinterpret_cast<sd_bus_get_fd_ptr>(dlsym(systemd_library, "sd_bus_get_fd"));
  sd_bus_flush_close_unref = reinterpret_cast<sd_bus_flush_close_unref_ptr>(dlsym(systemd_library, "sd_bus_flush_close_unref"));
  sd_bus_set_address = reinterpret_cast<sd_bus_set_address_ptr>(dlsym(systemd_library, "sd_bus_set_address"));
  sd_bus_message_append_strv = reinterpret_cast<sd_bus_message_append_strv_ptr>(dlsym(systemd_library, "sd_bus_message_append_strv"));
  sd_bus_message_read = reinterpret_cast<sd_bus_message_read_ptr>(dlsym(systemd_library, "sd_bus_message_read"));
  sd_bus_message_read_basic = reinterpret_cast<sd_bus_message_read_basic_ptr>(dlsym(systemd_library, "sd_bus_message_read_basic"));
  sd_bus_message_exit_container = reinterpret_cast<sd_bus_message_exit_container_ptr>(dlsym(systemd_library, "sd_bus_message_exit_container"));
  sd_bus_message_skip = reinterpret_cast<sd_bus_message_skip_ptr>(dlsym(systemd_library, "sd_bus_message_skip"));
  sd_bus_message_unref = reinterpret_cast<sd_bus_message_unref_ptr>(dlsym(systemd_library, "sd_bus_message_unref"));
  sd_bus_message_peek_type = reinterpret_cast<sd_bus_message_peek_type_ptr>(dlsym(systemd_library, "sd_bus_message_peek_type"));
  sd_bus_message_new_method_call = reinterpret_cast<sd_bus_message_new_method_call_ptr>(dlsym(systemd_library, "sd_bus_message_new_method_call"));
  sd_bus_call = reinterpret_cast<sd_bus_call_ptr>(dlsym(systemd_library, "sd_bus_call"));
  sd_bus_call_method = reinterpret_cast<sd_bus_call_method_ptr>(dlsym(systemd_library, "sd_bus_call_method"));
  sd_bus_message_enter_container = reinterpret_cast<sd_bus_message_enter_container_ptr>(dlsym(systemd_library, "sd_bus_message_enter_container"));
  // clang-format on

  if (sd_bus_default_system == nullptr ||
      sd_bus_set_allow_interactive_authorization == nullptr ||
      sd_bus_new == nullptr || sd_bus_start == nullptr ||
      sd_bus_get_fd == nullptr || sd_bus_flush_close_unref == nullptr ||
      sd_bus_set_address == nullptr || sd_bus_message_append_strv == nullptr ||
      sd_bus_message_read == nullptr || sd_bus_message_read_basic == nullptr ||
      sd_bus_message_exit_container == nullptr ||
      sd_bus_message_skip == nullptr || sd_bus_message_unref == nullptr ||
      sd_bus_message_peek_type == nullptr ||
      sd_bus_message_new_method_call == nullptr || sd_bus_call == nullptr ||
      sd_bus_call_method == nullptr ||
      sd_bus_message_enter_container == nullptr) {
    VLOG(1) << "Failed to locate a required function in the systemd library";
    return false;
  }

  return true;
}
} // namespace systemd_deps
