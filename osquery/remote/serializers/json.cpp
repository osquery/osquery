/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/json_parser.hpp>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"

namespace osquery {

Status JSONSerializer::serialize(const JSON& json, std::string& serialized) {
  return json.toString(serialized);
}

Status JSONSerializer::deserialize(const std::string& serialized, JSON& json) {
  if (serialized.empty()) {
    // Prevent errors from being thrown when a TLS endpoint accepts the JSON
    // payload, but doesn't respond with anything. This has been seen in the
    // wild, for example with Sumo Logic.
    json = JSON();
    return Status(0, "OK");
  }

  return json.fromString(serialized);
}
}
