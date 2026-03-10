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

enum class SeDebugPrivState { Enabled, Disabled };

// RAII guard that enables SeDebugPrivilege on construction and restores the
// original state when it goes out of scope.
class SeDebugPrivilegeGuard {
 private:
  SeDebugPrivState m_original_state = SeDebugPrivState::Disabled;
  bool m_privilege_enabled = false;
  bool m_needs_reset = false;

 public:
  SeDebugPrivilegeGuard();
  ~SeDebugPrivilegeGuard();

  // Non-copyable, non-movable
  SeDebugPrivilegeGuard(const SeDebugPrivilegeGuard&) = delete;
  SeDebugPrivilegeGuard& operator=(const SeDebugPrivilegeGuard&) = delete;
  SeDebugPrivilegeGuard(SeDebugPrivilegeGuard&&) = delete;
  SeDebugPrivilegeGuard& operator=(SeDebugPrivilegeGuard&&) = delete;

  // Returns true if the privilege was successfully enabled (or was already
  // enabled).
  bool privilegeEnabled() const;
};

} // namespace tables
} // namespace osquery
