/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/remote/http_client.h"
#include "osquery/utils/azure_util.h"

namespace pt = boost::property_tree;
namespace http = osquery::http;

namespace osquery {

std::string tree_get(pt::ptree& tree, const std::string key) {
  return tree.get<std::string>(key, "");
}


Status fetchAzureMetadata(pt::ptree& tree) {
  http::Client client;
  http::Request request(kAzureMetadataEndpoint);
  http::Response response;

  // NOTE(ww): Unlike EC2, Azure doesn't host only POSIX systems.
  // As such, we don't have a good platform independent way
  // to confirm whether the system we're on is, in fact,
  // an Azure instance.
  // Some ideas:
  // * Test for waagent and/or /var/log/waagent.log (Linux)
  // * Check for DHCP option 245 (Universal, but tedious)

  request << http::Request::Header("Metadata", "true");
  response = client.get(request);

  // Azure's metadata service is known to be spotty.
  if (response.result_int() == 404) {
    return Status(1, "Azure metadata service 404'd");
  }

  // Non-200s can indicate a variety of conditions, so report them.
  if (response.result_int() != 200) {
    return Status(1, std::string("Azure metadata service responded with ")
      + std::to_string(response.result_int()));
  }

  std::stringstream json_stream;
  json_stream << response.body();
  try {
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, "Couldn't parse JSON from: " + kAzureMetadataEndpoint + ": "
    + e.what());
  }

  return Status(0);
}

}
