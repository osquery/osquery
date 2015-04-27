/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <osquery/registry.h>

namespace osquery {

/**
 * @brief Superclass for enrollment plugins
 *
 * To interface with remote backends, first a client must be enrolled, this
 * happens through the remote facilities and this is the first step in that
 * process.
 *
 * Enrollment is called before any other function can be called. The purpose
 * of enrollment is to get a key from the server that uniquely identifies this
 * host.
 *
 * If the host if ever compromised and the key is no longer secret, the server
 * may revoke the key. At which point subsequent calls to non-enrollment
 * endpoints will fail. When this happens, enrollment should be called again
 * to receive a new key for continued use.
 */
class EnrollmentPlugin : public Plugin {
 public:
  /// The EnrollmentPlugin PluginRequest action router.
  Status call(const PluginRequest& request, PluginResponse& response);

 protected:
  virtual Status enroll() = 0;
  virtual std::string getKey(bool force) = 0;
};

/**
 * @brief Enrollment plugin registry.
 *
 * This creates an osquery registry for "emrollment" which may implement
 * EnrollmentPlugin. Only strings are logged in practice, and EnrollmentPlugin
 * provides a helper member for transforming PluginRequests to strings.
 */
CREATE_LAZY_REGISTRY(EnrollmentPlugin, "enrollment");
}
