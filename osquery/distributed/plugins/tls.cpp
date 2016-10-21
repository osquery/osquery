/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// clang-format off
// This must be here to prevent a WinSock.h exists error
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <vector>
#include <sstream>

#include <boost/property_tree/ptree.hpp>

#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_bool(tls_node_api);

FLAG(string,
     distributed_tls_read_endpoint,
     "",
     "TLS/HTTPS endpoint for distributed query retrieval");

FLAG(string,
     distributed_tls_write_endpoint,
     "",
     "TLS/HTTPS endpoint for distributed query results");

FLAG(uint64,
     distributed_tls_max_attempts,
     3,
     "Number of times to attempt a request")

class TLSDistributedPlugin : public DistributedPlugin {
 public:
  Status setUp() override;

  Status getQueries(std::string& json) override;

  Status writeResults(const std::string& json) override;

 protected:
  std::string read_uri_;
  std::string write_uri_;
};

REGISTER(TLSDistributedPlugin, "distributed", "tls");

Status TLSDistributedPlugin::setUp() {
  read_uri_ = TLSRequestHelper::makeURI(FLAGS_distributed_tls_read_endpoint);
  write_uri_ = TLSRequestHelper::makeURI(FLAGS_distributed_tls_write_endpoint);
  return Status(0, "OK");
}

Status TLSDistributedPlugin::getQueries(std::string& json) {
  pt::ptree params;
  params.put("_verb", "POST");
  return TLSRequestHelper::go<JSONSerializer>(
      read_uri_, params, json, FLAGS_distributed_tls_max_attempts);
}

Status TLSDistributedPlugin::writeResults(const std::string& json) {
  pt::ptree params;
  try {
    std::stringstream ss(json);
    pt::read_json(ss, params);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error parsing JSON: " + std::string(e.what()));
  }

  // The response is ignored.
  std::string response;
  return TLSRequestHelper::go<JSONSerializer>(
      write_uri_, params, response, FLAGS_distributed_tls_max_attempts);
}
}
