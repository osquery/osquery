/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/posix/errno.h>

#include <linux/bpf.h>

namespace osquery {
namespace ebpf {

Expected<bool, PosixError> isSupportedBySystem();

Expected<int, PosixError> syscall(int cmd, union bpf_attr* attr);

} // namespace ebpf
} // namespace osquery
