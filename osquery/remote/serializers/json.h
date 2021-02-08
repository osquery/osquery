/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
   * @brief See Serializer::deserialize
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
