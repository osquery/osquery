/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/enroll.h>
#include <osquery/flags.h>

namespace osquery {

/// Allow users to disable enrollment features.
FLAG(bool,
     disable_enrollment,
     false,
     "Disable enrollment functions on related config/logger plugins");

Status EnrollPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  if (FLAGS_disable_enrollment) {
    return Status(0, "Enrollment disabled");
  }

  // Only support the 'enroll' action.
  if (request.count("action") == 0 || request.at("action") != "enroll") {
    return Status(1, "Enroll plugins require an action");
  }

  // The caller may ask the enroll action to force getKey.
  bool force_enroll = false;
  if (request.count("force") && request.at("force") == "1") {
    force_enroll = true;
  }

  // The 'enroll' API should return a string and implement caching.
  auto key = this->enroll(force_enroll);
  response.push_back({{"key", key}});
  if (key.size() == 0) {
    return Status(1, "No enrollment key found/retrieved");
  } else {
    return Status(0, "OK");
  }
}
}
