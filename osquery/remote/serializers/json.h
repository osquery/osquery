/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/remote/requests.h>

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
