/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
