/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// This must be here to prevent a WinSock.h exists error
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <vector>
#include <sstream>

#include <osquery/distributed/distributed.h>
#include <osquery/remote/enroll/enroll.h>
#include <osquery/core/flags.h>
#include <osquery/registry/registry.h>

#include <osquery/utils/json/json.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/utility.h>

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
  JSON params;
  params.add("_verb", "POST");
  return TLSRequestHelper::go<JSONSerializer>(
      read_uri_, params, json, FLAGS_distributed_tls_max_attempts);
}

Status TLSDistributedPlugin::writeResults(const std::string& json) {
  JSON params;
  Status s = params.fromString(json);

  if (!s.ok()) {
    return s;
  }

  // The response is ignored.
  std::string response;
  return TLSRequestHelper::go<JSONSerializer>(
      write_uri_, params, response, FLAGS_distributed_tls_max_attempts);
}
}
