/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/remote/enroll/enroll.h>

namespace osquery {

class TLSEnrollPlugin : public EnrollPlugin {
 private:
  /// Enroll called, return cached key or if no key cached, call requestKey.
  std::string enroll() override;

 private:
  /// Request an enrollment key response from the TLS endpoint.
  Status requestKey(const std::string& uri, std::string& node_key);

 private:
  friend class TLSEnrollTests;
};
} // namespace osquery
