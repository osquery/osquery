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

#include <osquery/remote/http_client.h>
#include <osquery/utils/azure/azure_util.h>
#include <osquery/filesystem/filesystem.h>

namespace pt = boost::property_tree;
namespace http = osquery::http;
namespace fs = boost::filesystem;

namespace osquery {

static bool isAzureInstance() {
  static std::atomic<bool> checked(false);
  static std::atomic<bool> is_azure_instance(false);

  if (checked) {
    return is_azure_instance;
  }

  static std::once_flag once_flag;
  std::call_once(once_flag, []() {
    if (checked) {
      return;
    }

    checked = true;

#ifdef WINDOWS
    is_azure_instance = pathExists(fs::path("C:\\WindowsAzure")).ok();
#elif POSIX
    is_azure_instance = pathExists(fs::path("/var/log/waagent.log")).ok();
#else
    TLOG << "isAzureInstance(): unsupported platform: " << OSQUERY_BUILD_PLATFORM;
    is_azure_instance = false;
#endif
  });

  return is_azure_instance;
}

std::string tree_get(pt::ptree& tree, const std::string key) {
  return tree.get<std::string>(key, "");
}

Status fetchAzureMetadata(pt::ptree& tree) {
  if (!isAzureInstance()) {
    return Status(1, "Not an Azure instance");
  }

  http::Request request(kAzureMetadataEndpoint);
  http::Client::Options opts;
  http::Response response;

  opts.timeout(kAzureMetadataTimeout);
  http::Client client(opts);

  request << http::Request::Header("Metadata", "true");

  try {
    response = client.get(request);
  } catch (const std::system_error& e) {
    return Status(
        1, "Couldn't request " + kAzureMetadataEndpoint + ": " + e.what());
  }

  // Azure's metadata service is known to be spotty.
  if (response.result_int() == 404) {
    return Status(1, "Azure metadata service 404'd");
  }

  // Non-200s can indicate a variety of conditions, so report them.
  if (response.result_int() != 200) {
    return Status(1,
                  std::string("Azure metadata service responded with ") +
                      std::to_string(response.result_int()));
  }

  std::stringstream json_stream;
  json_stream << response.body();
  try {
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1,
                  "Couldn't parse JSON from: " + kAzureMetadataEndpoint + ": " +
                      e.what());
  }

  return Status(0);
}

} // namespace osquery
