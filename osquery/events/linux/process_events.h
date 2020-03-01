/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#ifdef __x86_64__
#include <asm/unistd_64.h>
#else
#include <asm/unistd.h>
#endif

#include <set>

namespace osquery {
const std::set<int> kExecProcessEventsSyscalls = {__NR_execve, __NR_execveat};

const std::set<int> kForkProcessEventsSyscalls = {
#ifndef __aarch64__
    __NR_fork, __NR_vfork,
#endif
    __NR_clone};
} // namespace osquery
