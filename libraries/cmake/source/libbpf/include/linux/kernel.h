/*
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

// Include the next linux/kernel.h in the path
#include_next <linux/kernel.h>

#ifdef __cplusplus
// If we are in C++, we might be using LLVM headers that conflict with min/max macros.
// We undefine them here to allow std::min/std::max to work.
#if defined(min)
#undef min
#endif

#if defined(max)
#undef max
#endif
#endif

// Ensure struct sysinfo is defined. Some versions of linux/kernel.h in the toolchain
// include linux/sysinfo.h, but the version in libbpf may shadow it.
#include <linux/sysinfo.h>
