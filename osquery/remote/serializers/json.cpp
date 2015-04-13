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
  std::ostringstream ss;
  try {
    pt::write_json(ss, params, false);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  serialized = ss.str();
  return Status(0, "OK");
}

Status JSONSerializer::deserialize(const std::string& serialized,
                                   pt::ptree& params) {
  std::stringstream j;
  j << serialized;
  try {
    pt::read_json(j, params);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}
}
