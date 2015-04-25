/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <sstream>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>
#include <osquery/registry.h>
#include "osquery/remote/requests.h"
#include "osquery/remote/transports/http.h"
#include "osquery/remote/serializers/json.h"

#define MAX_TRIES 5

namespace osquery {

DECLARE_string(enrollment_app_id);

FLAG(string,
     config_enrollment_uri,
     "Not Specified",
     "The endpoint for server side client enrollment");

class HTTPConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config);
};

REGISTER(HTTPConfigPlugin, "config", "http");

Status runEnrollment(const bool force = false) {
  PluginResponse resp;
  PluginRequest req;
  if (force) {
    req = {{"enroll", "1"}};
  } else {
    req = {{"enroll", "0"}};
  }
  Status stat = Registry::call("enrollment", "get_key", req, resp);

  if (!stat.ok()) {
    return stat;
  }
  if (resp.size() > 0 && resp[0]["key"].length() == 0) {
    return Status(1, "Enrollment Error: No Key");
  }
  return Status(0, "OK");
}

Status getConfig(boost::property_tree::ptree& recv) {
  // Make request to endpoint with secrets
  auto r = Request<HTTPTransport, JSONSerializer>(FLAGS_config_enrollment_uri);
  boost::property_tree::ptree params;

  PluginResponse resp;
  Status stat =
      Registry::call("enrollment", "get_key", {{"enroll", "0"}}, resp);

  params.put<std::string>("enrollment_key", resp[0]["key"]);
  params.put<std::string>("app_id", FLAGS_enrollment_app_id);
  stat = r.call(params);

  if (!stat.ok()) {
    return stat;
  }
  // The call was ok, so store the enrolled key
  stat = r.getResponse(recv);
  if (!stat.ok()) {
    return stat;
  }
  // Receive config or key rejection
  if (recv.count("enrollment_invalid") > 0 &&
      recv.get<std::string>("enrollment_invalid", "") == "1") {
    return stat;
  }
  return Status(0, "OK");
}

Status HTTPConfigPlugin::genConfig(std::map<std::string, std::string>& config) {
  boost::property_tree::ptree recv;
  for (int i = 0; i <= MAX_TRIES; i++) {
    if (i == MAX_TRIES) {
      return Status(1, "Could not get config");
    }
    if (runEnrollment(i == 0).ok() && getConfig(recv).ok()) {
      break;
    }
  }
  std::stringstream ss;
  write_json(ss, recv);
  config[FLAGS_enrollment_app_id] = ss.str();
  return Status(0, "OK");
}
}
