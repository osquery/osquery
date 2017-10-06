/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <osquery/status.h>

namespace osquery {

/**
 * @brief Install osqueryd as a service for the platform.
 *
 * Currently, this is only used by Windows. POSIX platforms use a companion
 * script called osquerycrl to move files and install launch daemons or init
 * scripts/systemd units.
 *
 * This disconnect of install flows is a limitation. The POSIX install flows
 * should be refactored into install/uninstall service methods.
 */
Status installService(const char* const path);

/// See installService.
Status uninstallService();

/// Begin the platform-agnostic shell and daemon initialization.
int startOsquery(int argc,
                 char* argv[],
                 std::function<void()> shutdown = nullptr);
} // namespace osquery
