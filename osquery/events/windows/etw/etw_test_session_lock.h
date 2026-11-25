/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>

#include <osquery/utils/status/status.h>
#include <osquery/utils/system/system.h>

namespace osquery {

/**
 * @brief Serializes test processes that use host-wide ETW session names.
 *
 * Owns a Windows named mutex for the controller's lifetime. Acquisition and
 * destruction must occur on the main test thread, with destruction after ETW
 * session teardown. Abandoned ownership is accepted so initialization can
 * reclaim trace sessions left by a crashed test.
 */
class EtwTestSessionLock final {
 public:
  static Status acquire(std::unique_ptr<EtwTestSessionLock>& lock);
  ~EtwTestSessionLock();

 private:
  explicit EtwTestSessionLock(HANDLE handle) : handle_(handle) {}
  EtwTestSessionLock(const EtwTestSessionLock&) = delete;
  EtwTestSessionLock& operator=(const EtwTestSessionLock&) = delete;

  HANDLE handle_;
};

} // namespace osquery
