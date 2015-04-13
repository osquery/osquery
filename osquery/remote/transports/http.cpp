/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/network/protocol/http/client.hpp>

#include "osquery/remote/transports/http.h"

using namespace boost::network;

namespace osquery {

void HTTPTransport::decorateRequest(http::client::request& r) {
  r << header("Connection", "close");
  r << header("Content-Type", serializer_->getContentType());
}

Status HTTPTransport::sendRequest() {
  http::client client;
  http::client::request r(destination_);
  decorateRequest(r);
  response_ = client.get(r);
  response_status_ =
      serializer_->deserialize(body(response_), response_params_);
  return response_status_;
}

Status HTTPTransport::sendRequest(const std::string& params) {
  http::client client;
  http::client::request r(destination_);
  decorateRequest(r);
  response_ = client.post(r, params);
  response_status_ =
      serializer_->deserialize(body(response_), response_params_);
  return response_status_;
}
}
