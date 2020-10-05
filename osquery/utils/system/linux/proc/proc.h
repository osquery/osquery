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

#include <osquery/utils/status/status.h>

namespace osquery {
namespace proc {

std::string cmdline(pid_t pid);

/*
 * Use SYS_setns syscall to set namespace.
 * Considers these situations:
 *  - early in startup as shell if --setns flag set
 *  - in shell when using `.setns` command
 *  - running queries in container (in future ?)
 *
 * NOTE: setns() function not added until glibc 2.14
 * Requires that process is single-threaded.
 * To accomodate callers, his function does not log
 * anything, but will provide INFO level in feedback
 * and error message in status when failure.
 */
Status setLinuxNamespace(const char* cpath, std::string& feedback);

} // namespace proc
} // namespace osquery
