/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/enrollment.h>

namespace osquery {

Status EnrollmentPlugin::call(const PluginRequest& request,
                              PluginResponse& response) {
  if (request.count("enroll") == 0) {
    return Status(1, "Unsupported call to enrollment plugin");
  }

  std::string key = this->getKey(request.at("enroll") == "1");
  response.push_back({{"key", key}});
  if (key == "") {
    return Status(1, "Could not enroll");
  } else {
    return Status(0, "OK");
  }
}
}
