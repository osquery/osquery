/*
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

/*
 * Stub for <linux/bpf_perf_event.h> for toolchains that do not provide it.
 * bpf_user_pt_regs_t is defined in pt_regs_fix.h which is force-included
 * for all libbpf compilation units.
 */

#include <linux/types.h>

struct bpf_perf_event_data {
  bpf_user_pt_regs_t regs;
  __u64 sample_period;
  __u64 addr;
};
