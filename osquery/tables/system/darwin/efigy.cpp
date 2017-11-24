/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/remote/http_client.h"
#include "osquery/tables/system/hash.h"

namespace pt = boost::property_tree;

namespace {
struct SystemInformation final {
  std::string board_id;
  std::string smc_ver;
  std::string sys_uuid;
  std::string build_num;
  std::string rom_ver;
  std::string hw_ver;
  std::string os_ver;
  std::string mac_addr;
};

struct ServerResponse final {
  std::string latest_efi_version;
  std::string latest_os_version;
  std::string latest_build_number;
};

osquery::Status getSystemInformation(SystemInformation& system_info) {
  system_info.board_id = "Mac-XXXXXXXXXXXXXXXX";
  system_info.smc_ver = "2.44f1";
  system_info.sys_uuid = "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
  system_info.build_num = "17B48";
  system_info.rom_ver = "MBP142.0167.B00";
  system_info.hw_ver = "MacBookPro14,2";
  system_info.os_ver = "10.13.1";
  system_info.mac_addr = "0x0123456789ab";

  return osquery::Status(0, "OK");
}

osquery::Status getPostRequestData(std::string& json,
                                   const SystemInformation& system_info) {
  json.clear();

  if (system_info.smc_ver.empty() || system_info.build_num.empty() ||
      system_info.hw_ver.empty() || system_info.os_ver.empty() ||
      system_info.sys_uuid.empty() || system_info.mac_addr.empty()) {
    return osquery::Status(1, "Incomplete SystemInformation object received");
  }

  pt::ptree system_info_object;
  system_info_object.put("board_id", system_info.board_id);
  system_info_object.put("smc_ver", system_info.smc_ver);

  {
    std::string buffer = system_info.mac_addr + system_info.sys_uuid;
    osquery::Hash hasher(osquery::HASH_TYPE_SHA256);
    hasher.update(buffer.data(), buffer.size());
    system_info_object.put("hashed_uuid", hasher.digest());
  }

  system_info_object.put("build_num", system_info.build_num);
  system_info_object.put("rom_ver", system_info.rom_ver);
  system_info_object.put("hw_ver", system_info.hw_ver);
  system_info_object.put("os_ver", system_info.os_ver);

  // this identifier only makes sense when posting more than one query in
  // a single request
  std::string system_identifier = "127.0.0.1";

  pt::ptree root_object;
  root_object.push_back(
      pt::ptree::value_type(system_identifier, system_info_object));

  std::stringstream json_stream;
  pt::json_parser::write_json(json_stream, root_object);

  json = json_stream.str();
  return osquery::Status(0, "OK");
}

osquery::Status queryServer(ServerResponse& response,
                            const SystemInformation& system_info) {
  const char* efigy_api_url = "https://api.efigy.io";

  std::string request_data;
  auto status = getPostRequestData(request_data, system_info);
  if (!status.ok()) {
    return status;
  }

  // todo: bundle the cert!
  osquery::http::Client::Options client_options;
  client_options.openssl_verify_path("/Users/alessandro/Desktop/cacert.pem")
      .always_verify_peer(true)
      .openssl_options(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);

  client_options.timeout(5).follow_redirects(true);

  try {
    osquery::http::Request server_request(efigy_api_url);
    server_request << osquery::http::Request::Header("User-Agent", "osquery");

    osquery::http::Client client(client_options);
    auto server_response = client.post(server_request, request_data);

    auto json_output = server_response.body();
    VLOG(1) << json_output;

    return osquery::Status(0, "OK");

  } catch (const std::exception& e) {
    VLOG(1) << e.what();
    return osquery::Status(
        0, std::string("Could not query the EFIgy API endpoint: ") + e.what());
  }
}
} // namespace

namespace osquery {
namespace tables {
QueryData queryEFIgy(QueryContext& context) {
  SystemInformation system_info;
  auto status = getSystemInformation(system_info);
  if (!status.ok()) {
    VLOG(1)
        << "Failed to obtain the required system information. Error output: "
        << status.getMessage();

    Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";
    return {r};
  }

  ServerResponse response;
  status = queryServer(response, system_info);
  if (!status.ok()) {
    VLOG(1) << "Failed to query the EFIgy API endpoint. Error output: "
            << status.getMessage();

    Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";
    return {r};
  }

  Row r;
  r["latest_efi_version"] = response.latest_efi_version;
  r["efi_version"] = system_info.rom_ver;
  if (system_info.rom_ver == response.latest_efi_version) {
    r["efi_version_status"] = "success";
  } else {
    r["efi_version_status"] = "failure";
  }

  r["latest_os_version"] = response.latest_os_version;
  r["os_version"] = system_info.os_ver;
  if (system_info.os_ver == response.latest_os_version) {
    r["os_version_status"] = "success";
  } else {
    r["os_version_status"] = "failure";
  }

  r["latest_build_number"] = response.latest_build_number;
  r["build_number"] = system_info.build_num;
  if (system_info.build_num == response.latest_build_number) {
    r["build_number_status"] = "success";
  } else {
    r["build_number_status"] = "failure";
  }

  return {r};
}
} // namespace tables
} // namespace osquery
