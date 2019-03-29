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

#include <osquery/experimental/tracing/linux/syscall_event.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/ebpf/map.h>
#include <osquery/utils/system/linux/ebpf/program.h>

namespace osquery {
namespace events {

using PerfEventCpuMap = ebpf::Map<int, int, BPF_MAP_TYPE_PERF_EVENT_ARRAY>;

Expected<ebpf::Program, ebpf::Program::Error> genLinuxProgram(
    enum bpf_prog_type prog_type,
    PerfEventCpuMap const& cpu_map,
    syscall::EventType type);

} // namespace events
} // namespace osquery
