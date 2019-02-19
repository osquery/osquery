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

const std::set<int> kProcessEventsSyscalls = {
  __NR_execve};
