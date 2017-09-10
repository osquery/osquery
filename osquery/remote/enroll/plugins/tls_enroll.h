
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

#include <osquery/enroll.h>

namespace osquery {

/**
 * @brief These tables populate the "host_details" content.
 *
 * Enrollment plugins should send 'default' host details to enroll request
 * endpoints. This allows the enrollment service to identify the new node.
 */
extern const std::set<std::string> kEnrollHostDetails;

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
