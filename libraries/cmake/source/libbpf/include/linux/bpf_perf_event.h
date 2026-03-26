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
 * On aarch64, struct pt_regs and bpf_user_pt_regs_t are defined in
 * pt_regs_fix.h which is force-included for all libbpf compilation units.
 * On x86/x86_64, bpf_user_pt_regs_t aliases struct pt_regs from asm/ptrace.h.
 */

#include <linux/types.h>

struct bpf_perf_event_data {
  bpf_user_pt_regs_t regs;
  __u64 sample_period;
  __u64 addr;
};
