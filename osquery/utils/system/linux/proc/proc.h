/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <boost/filesystem/path.hpp>

#include <string>

namespace osquery {
namespace proc {

std::string cmdline(pid_t pid);

} // namespace proc
} // namespace osquery
