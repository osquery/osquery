/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <asm/unistd_64.h>

#include <set>

namespace osquery {
const std::set<int> kExecProcessEventsSyscalls = {__NR_execve, __NR_execveat};

const std::set<int> kForkProcessEventsSyscalls = {
    __NR_fork, __NR_vfork, __NR_clone};
} // namespace osquery
