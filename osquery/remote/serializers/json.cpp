/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"

namespace pt = boost::property_tree;

namespace osquery {

Status JSONSerializer::serialize(const pt::ptree& params,
                                 std::string& serialized) {
  std::ostringstream output;
  try {
    pt::write_json(output, params, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, std::string("JSON serialize error: ") + e.what());
  }
  serialized = output.str();
  return Status(0, "OK");
}

Status JSONSerializer::deserialize(const std::string& serialized,
                                   pt::ptree& params) {
  if (serialized.empty()) {
    // Prevent errors from being thrown when a TLS endpoint accepts the JSON
    // payload, but doesn't respond with anything. This has been seen in the
    // wild, for example with Sumo Logic.
    params = pt::ptree();
    return Status(0, "OK");
  }
  try {
    std::stringstream input;
    input << serialized;
    pt::read_json(input, params);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, std::string("JSON deserialize error: ") + e.what());
  }
  return Status(0, "OK");
}
}
