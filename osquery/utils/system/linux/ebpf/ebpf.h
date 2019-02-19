/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
