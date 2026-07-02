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
 * bpf_user_pt_regs_t is pre-declared by pt_regs_fix.h (force-included for all
 * libbpf compilation units). Including asm/ptrace.h here completes the struct
 * definition so it can be used as a field below.
 *
 * On x86/x86_64, asm/ptrace.h defines struct pt_regs.
 * On aarch64, asm/ptrace.h defines struct user_pt_regs.
 */

#include <asm/ptrace.h>
#include <linux/types.h>

struct bpf_perf_event_data {
  bpf_user_pt_regs_t regs;
  __u64 sample_period;
  __u64 addr;
};
