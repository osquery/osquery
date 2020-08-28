/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "json.h"

#include <osquery/utils/json/json.h>

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
    return Status::success();
  }

  return json.fromString(serialized);
}
}
