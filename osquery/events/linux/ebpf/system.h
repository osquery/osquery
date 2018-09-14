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

#include <linux/bpf.h>
#include <linux/version.h>

#ifndef __NR_perf_event_open
#if defined(__PPC__)
#define __NR_perf_event_open 319
#elif defined(__i386__)
#define __NR_perf_event_open 336
#elif defined(__x86_64__)
#define __NR_perf_event_open 298
#else
#error __NR_perf_event_open is undefined, probably this arch is not supported.
#endif
#endif

#ifndef __NR_bpf
#if defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__sparc__)
#define __NR_bpf 349
#elif defined(__s390__)
#define __NR_bpf 351
#else
#error __NR_bpf is undefined, probably this arch is not supported.
#endif
#endif

namespace osquery {
namespace ebpf {

bool isSupportedBySystem();

namespace impl {

struct KernelReleaseVersion {
  int major = 0;
  int minor = 0;
  int patches = 0;
};

KernelReleaseVersion getKernelReleaseVersion();

} // namespace impl

} // namespace ebpf
} // namespace osquery
