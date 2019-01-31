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

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/ebpf/program.h>

namespace osquery {
namespace events {

namespace syscall {

enum class Type : __s32 {
  Unknown = 0,
  KillEnter = 1,
};

static constexpr std::size_t kCommSize = 16u;

struct Event {
  Type type; // ebpf offset depends on the struct type in the unit
  __s32 pid;
  __s32 tgid;

  union Body {
    struct KillEnter {
      /* -44 type */
      /* -40 pid */
      /* -36 tgid */
      /* -32 */ char comm[kCommSize];
      /* -16 */ __s32 arg_pid;
      /* -12 */ __s32 arg_sig;
      /*  -8 */ __u32 uid;
      /*  -4 */ __u32 gid;
    } kill_enter;
  } body;
};

} // namespace syscall
} // namespace events
} // namespace osquery
