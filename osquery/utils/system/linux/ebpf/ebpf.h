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
#include <osquery/utils/system/posix/errno.h>

#include <linux/bpf.h>

namespace osquery {
namespace ebpf {

Expected<bool, PosixError> isSupportedBySystem();

Expected<int, PosixError> syscall(int cmd, union bpf_attr* attr);

} // namespace ebpf
} // namespace osquery
