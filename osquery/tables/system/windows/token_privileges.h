/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#pragma once

#include <mutex>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

enum class SeDebugPrivState { NotSet, Enabled, Disabled };

// RAII guard that enables SeDebugPrivilege on construction and restores the
// original state when it goes out of scope.
class SeDebugPrivilegeGuard {
 private:
  inline static SeDebugPrivState s_original_state;
  inline static std::mutex s_mutex;
  inline static bool s_needs_reset;
  inline static int s_ref_count;

 public:
  SeDebugPrivilegeGuard() noexcept;
  ~SeDebugPrivilegeGuard() noexcept;

  // Non-copyable, non-movable
  SeDebugPrivilegeGuard(const SeDebugPrivilegeGuard&) = delete;
  SeDebugPrivilegeGuard& operator=(const SeDebugPrivilegeGuard&) = delete;
  SeDebugPrivilegeGuard(SeDebugPrivilegeGuard&&) = delete;
  SeDebugPrivilegeGuard& operator=(SeDebugPrivilegeGuard&&) = delete;

  // For testing purposes, returns the number of active guards. The privilege
  // should only be disabled when the ref count drops to 0.
  int refCount() const;
};

// Helper function to get the current state of the SeDebugPrivilege.  Only the
// getDebugTokenPrivilegeState function is exposed publicly since the
// SeDebugPrivilegeGuard will handle setting and resetting the privilege as
// needed.
SeDebugPrivState getDebugTokenPrivilegeState() noexcept;

} // namespace tables
} // namespace osquery
