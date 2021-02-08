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

#include <osquery/utils/status/status.h>

namespace osquery {

/**
 * @brief Install osqueryd as a service for the platform.
 *
 * Currently, this is only used by Windows. POSIX platforms use a companion
 * script called osquerycrtl to move files and install launch daemons or init
 * scripts/systemd units.
 *
 * This disconnect of install flows is a limitation. The POSIX install flows
 * should be refactored into install/uninstall service methods.
 */
Status installService(const std::string& path);

/// See installService.
Status uninstallService();

/// Begin the platform-agnostic shell and daemon initialization.
int startOsquery(int argc, char* argv[]);
} // namespace osquery
