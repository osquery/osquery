/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/filesystem.h>

namespace osquery {

/// Allow users to disable enrollment features.
CLI_FLAG(bool,
         disable_enrollment,
         false,
         "Disable enrollment functions on related config/logger plugins");

/// Path to optional enrollment secret data, sent with enrollment requests.
CLI_FLAG(string,
         enroll_secret_path,
         "",
         "Path to an optional client enrollment-auth secret");

/// Name of optional environment variable holding enrollment secret data.
CLI_FLAG(string,
         enroll_secret_env,
         "",
         "Name of environment variable holding enrollment-auth secret");

/// Allow users to disable reenrollment if a config/logger endpoint fails.
CLI_FLAG(bool,
         disable_reenrollment,
         false,
         "Disable re-enrollment attempts if related plugins return invalid");

Status clearNodeKey() {
  std::string node_key;
  auto s = getDatabaseValue(kPersistentSettings, "nodeKey", node_key);
  if (!s.ok()) {
    return s;
  }

  if (node_key.size() > 0) {
    return deleteDatabaseValue(kPersistentSettings, "nodeKey");
  }

  return Status(0, "OK");
}

std::string getNodeKey(const std::string& enroll_plugin) {
  std::string node_key;
  getDatabaseValue(kPersistentSettings, "nodeKey", node_key);
  if (node_key.size() > 0) {
    // A non-empty node key was found in the backing-store (cache).
    return node_key;
  }

  // The node key request time is recorded before the enroll request occurs.
  auto request_time = std::to_string(getUnixTime());

  // Request the enroll plugin's node secret.
  PluginResponse response;
  Registry::call("enroll", enroll_plugin, {{"action", "enroll"}}, response);
  if (response.size() > 0 && response[0].count("node_key") != 0) {
    node_key = response[0].at("node_key");
    setDatabaseValue(kPersistentSettings, "nodeKey", node_key);
    // Set the last time a nodeKey was requested from an enrollment endpoint.
    setDatabaseValue(kPersistentSettings, "nodeKeyTime", request_time);
  }
  return node_key;
}

const std::string getEnrollSecret() {
  std::string enrollment_secret;

  if (FLAGS_enroll_secret_path != "") {
    osquery::readFile(FLAGS_enroll_secret_path, enrollment_secret);
    boost::trim(enrollment_secret);
  } else {
    const char* env_secret = std::getenv(FLAGS_enroll_secret_env.c_str());
    if (env_secret != nullptr) {
      enrollment_secret = std::string(env_secret);
    }
  }

  return enrollment_secret;
}

Status EnrollPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  if (FLAGS_disable_enrollment) {
    return Status(0, "Enrollment disabled");
  }

  // Only support the 'enroll' action.
  if (request.count("action") == 0 || request.at("action") != "enroll") {
    return Status(1, "Enroll plugins require an action");
  }

  // The 'enroll' API should return a string and implement caching.
  auto node_key = this->enroll();
  response.push_back({{"node_key", node_key}});
  if (node_key.size() == 0) {
    return Status(1, "No enrollment key found/retrieved");
  } else {
    return Status(0, "OK");
  }
}
}
