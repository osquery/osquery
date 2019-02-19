/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/enroll.h>

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
}
