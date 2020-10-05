/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/filesystem/path.hpp>

#include <string>

namespace osquery {
namespace proc {

std::string cmdline(pid_t pid);

} // namespace proc
} // namespace osquery
