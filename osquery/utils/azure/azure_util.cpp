/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Keep this included first (See #6507).
#include <osquery/remote/http_client.h>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/azure/azure_util.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/json/json.h>

#include <mutex>

namespace http = osquery::http;
namespace fs = boost::filesystem;

namespace osquery {

// 2018-02-01 is supported across all Azure regions, according to MS.
const std::string kAzureMetadataEndpoint =
    "http://" + http::kInstanceMetadataAuthority +
    "/metadata/instance/compute?api-version=2018-02-01";

// 3 seconds should be more than enough time for the metadata endpoint to
// respond.
const int kAzureMetadataTimeout = 3;

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

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      is_azure_instance = pathExists(fs::path("C:\\WindowsAzure")).ok();
    } else if (isPlatform(PlatformType::TYPE_POSIX)) {
      is_azure_instance = pathExists(fs::path("/var/log/waagent.log")).ok();
    } else {
      TLOG << "Unsupported Azure platform: " << OSQUERY_PLATFORM;
      is_azure_instance = false;
    }
  });

  return is_azure_instance;
}

std::string getAzureKey(JSON& doc, const std::string& key) {
  if (!doc.doc().HasMember(key)) {
    return {};
  }

  if (!doc.doc()[key].IsString()) {
    return {};
  }

  return doc.doc()[key].GetString();
}

Status fetchAzureMetadata(JSON& doc) {
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

  // Non-200s can indicate a variety of conditions, so report them.
  if (response.result_int() != 200) {
    return Status(1,
                  std::string("Azure metadata service responded with ") +
                      std::to_string(response.result_int()));
  }

  auto s = doc.fromString(response.body());
  if (!s.ok()) {
    return s;
  }

  if (!doc.doc().IsObject()) {
    return Status(1, "Azure metadata service response isn't a JSON object");
  }

  return s;
}

} // namespace osquery
