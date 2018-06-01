/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include "osquery/remote/requests.h"

namespace osquery {

/**
 * @brief JSON Serializer
 */
class JSONSerializer : public Serializer {
 public:
  /**
   * @brief See Serializer::serialize
   */
  Status serialize(const JSON& json, std::string& serialized);

  /**
   * @brief See Serializer::desiralize
   */
  Status deserialize(const std::string& serialized, JSON& json);

  /**
   * @brief See Serializer::getContentType
   *
   * @return The content type
   */
  std::string getContentType() const { return "application/json"; }
};
}
