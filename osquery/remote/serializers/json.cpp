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

#include "osquery/remote/serializers/json.h"

namespace pt = boost::property_tree;

namespace osquery {

Status JSONSerializer::serialize(const pt::ptree& params,
                                 std::string& serialized) {
  std::ostringstream output;
  try {
    pt::write_json(output, params, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, e.what());
  }
  serialized = output.str();
  return Status(0, "OK");
}

Status JSONSerializer::deserialize(const std::string& serialized,
                                   pt::ptree& params) {
  try {
    std::stringstream input;
    input << serialized;
    pt::read_json(input, params);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}
}
