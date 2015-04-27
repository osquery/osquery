/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/enrollment.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/http.h"
#include "osquery/remote/serializers/json.h"

#define MAX_TRIES 5

namespace osquery {

FLAG(string,
     enrollment_uri,
     "Not Specified",
     "The endpoint for server side client enrollment");

FLAG(string,
     enrollment_secret,
     "Not Specified",
     "The secret to be provided to the endpoint to faciliate enrollment");

FLAG(string,
     enrollment_app_id,
     "Not Specified",
     "The identification number of the application");

class RemoteEnrollmentPlugin : public EnrollmentPlugin {
 public:
  std::string getKey(bool force);

 private:
  Status enroll();
  std::string enrollment_key_;
};

REGISTER(RemoteEnrollmentPlugin, "enrollment", "get_key");

Status RemoteEnrollmentPlugin::enroll() {
  auto r = Request<HTTPTransport, JSONSerializer>(FLAGS_enrollment_uri);
  boost::property_tree::ptree params;
  params.put<std::string>("secret", FLAGS_enrollment_secret);
  params.put<std::string>("app_id", FLAGS_enrollment_app_id);
  auto stat = r.call(params);
  if (!stat.ok()) {
    return stat;
  }
  // The call was ok, so store the enrolled key
  boost::property_tree::ptree recv;
  stat = r.getResponse(recv);
  if (!stat.ok()) {
    return stat;
  }
  if (recv.count("enrollment_key") > 0) {
    enrollment_key_ = recv.get<std::string>("enrollment_key", "");
    return Status(0, "OK");
  } else {
    return Status(1, "No key");
  }
}

std::string RemoteEnrollmentPlugin::getKey(bool force) {
  if (enrollment_key_.length() == 0 || force) {
    VLOG(1) << "Querying server for enrollment key...";
    for (int i = 1; i <= MAX_TRIES; i++) {
      if (enroll().ok()) {
        break;
      }
      if (i == MAX_TRIES) {
        return "";
      }
      sleep(i * i);
    }
  }
  return enrollment_key_;
}
}
