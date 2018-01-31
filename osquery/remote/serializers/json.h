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
   * @brief Serialize a property tree into a string
   *
   * @param params A property tree of parameters
   *
   * @param serialized The string to populate the final serialized params into
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status serialize(const boost::property_tree::ptree& params,
                   std::string& serialized);

  /**
   * @brief Deerialize a property tree into a property tree
   *
   * @param params A string of serialized parameters
   *
   * @param serialized The property tree to populate the final serialized
   * params into
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status deserialize(const std::string& serialized,
                     boost::property_tree::ptree& params);

  /**
   * @brief Returns the HTTP content type, for HTTP/TLS transport
   *
   * @return The content type
   */
  std::string getContentType() const { return "application/json"; }
};
}
