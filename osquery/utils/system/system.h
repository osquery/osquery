/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#ifdef OSQUERY_WINDOWS
#include <osquery/utils/system/windows/system.h>
#elif OSQUERY_POSIX
#include <osquery/utils/system/posix/system.h>
#endif

namespace osquery {
/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief Getter for a host's fully qualified domain name
 *
 * @return a string representation of the hosts fully qualified domain name
 * if the host is joined to a domain, otherwise it simply returns the hostname
 */
std::string getFqdn();
} // namespace osquery
