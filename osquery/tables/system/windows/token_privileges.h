/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#pragma once

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

// The state of the SeDebugPrivilege for a token.
enum class SeDebugPrivState { Enabled, Disabled };

// Get the state of the SeDebugPrivilege for the current process token.
SeDebugPrivState getDebugTokenPrivilegeState();

// Enable or disable the SeDebugPrivilege for the current process token based on
// the specified state. Returns true on success, false on failure.
bool setDebugTokenPrivilege(SeDebugPrivState state);

} // namespace tables
} // namespace osquery
