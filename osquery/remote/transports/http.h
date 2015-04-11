/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <boost/network/protocol/http/client.hpp>

#include "osquery/remote/requests.h"

namespace osquery {

/**
 * @brief HTTP transport
 */
class HTTPTransport : public Transport {
 public:
  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status sendRequest();

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A string representing the serialized parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status sendRequest(const std::string& params);

  /**
   * @brief Class destructor
  */
  ~HTTPTransport() {}

 protected:
  /**
    * @brief Modify a request object with base modifications
    *
    * @param The request object, to be modified
    */
  void decorateRequest(boost::network::http::client::request& r);

 protected:
  /// Storage for the HTTP response object
  boost::network::http::client::response response_;
};
}
