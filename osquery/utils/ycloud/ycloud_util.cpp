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

#include <boost/algorithm/string.hpp>
#include <osquery/core/core.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/ycloud/ycloud_util.h>

namespace http = osquery::http;

namespace osquery {

const std::string kYCloudMetadataPathAndQuery =
    "/computeMetadata/v1/instance/?alt=json&recursive=true";
const std::string kAttributes = "attributes";
const int kYCloudMetadataTimeout = 3;

std::tuple<std::string, std::string> getFolderIdAndZoneFromZoneField(
    const std::string& zone) {
  if (boost::algorithm::starts_with(zone, "projects/")) {
    auto s = osquery::split(zone, "/");
    if (s.size() >= 4) {
      return {s[1], s[3]};
    }
  }

  return {"", ""};
}

std::string getSerialPortEnabled(JSON& doc) {
  const std::string kSerialPortFlag = "serial-port-enable";

  if (!doc.doc().HasMember(kAttributes)) {
    return "";
  }

  if (!doc.doc()[kAttributes].IsObject()) {
    return "";
  }

  if (!doc.doc()[kAttributes].HasMember(kSerialPortFlag)) {
    return "";
  }

  if (!doc.doc()[kAttributes][kSerialPortFlag].IsString()) {
    return "";
  }

  return doc.doc()[kAttributes][kSerialPortFlag].GetString();
}

std::string getYCloudSshKey(JSON& doc) {
  const std::string kSshKeys = "ssh-keys";

  if (!doc.doc().HasMember(kAttributes)) {
    return "";
  }

  if (!doc.doc()[kAttributes].IsObject()) {
    return "";
  }

  if (!doc.doc()[kAttributes].HasMember(kSshKeys)) {
    return "";
  }

  if (!doc.doc()[kAttributes][kSshKeys].IsString()) {
    return "";
  }

  return doc.doc()[kAttributes][kSshKeys].GetString();
}

std::string getYCloudKey(JSON& doc, const std::string& key) {
  if (!doc.doc().HasMember(key)) {
    return "";
  }

  if (!doc.doc()[key].IsString()) {
    return "";
  }

  return doc.doc()[key].GetString();
}

Status fetchYCloudMetadata(JSON& doc, const std::string& endpoint) {
  http::Request request(endpoint + kYCloudMetadataPathAndQuery);
  http::Client::Options opts;
  http::Response response;

  opts.timeout(kYCloudMetadataTimeout);
  http::Client client(opts);

  request << http::Request::Header("Metadata-Flavor", "Google");

  try {
    response = client.get(request);
  } catch (const std::system_error& e) {
    return Status(1, "Couldn't request " + endpoint + ": " + e.what());
  }

  if (response.result_int() != 200) {
    return Status(1,
                  "YCloud metadata service responded with " +
                      std::to_string(response.result_int()));
  }

  auto s = doc.fromString(response.body());
  if (!s.ok()) {
    return s;
  }

  if (!doc.doc().IsObject()) {
    return Status(1, "YCloud metadata service response isn't a JSON object");
  }

  return Status::success();
}

} // namespace osquery