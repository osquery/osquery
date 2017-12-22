/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>

#include <iostream>
#include <sstream>
#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/optional/optional.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
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

std::string getSMCVersionField(const std::string& raw_version_field,
                               size_t index) {
  if (raw_version_field.size() != 12U) {
    return std::string();
  }

  size_t field_index;
  size_t field_size;

  if (index <= 2U) {
    field_index = index * 2U;
    field_size = 2U;

  } else if (index == 3U) {
    field_index = 6U;
    field_size = std::string::npos;

  } else {
    return std::string();
  }

  auto value = raw_version_field.substr(field_index, field_size);
  value.erase(0, value.find_first_not_of('0'));
  if (value.empty()) {
    value = "0";
  }

  return value;
}

osquery::Status getEFIVersion(std::string& version) {
  version.clear();

  auto platform_info = osquery::SQL::selectAllFrom("platform_info");
  if (platform_info.empty()) {
    return osquery::Status(1, "Failed to list the platform information");
  }

  std::stringstream stream(platform_info[0]["version"]);

  std::vector<std::string> fields;
  for (std::string s; std::getline(stream, s, '.'); fields.push_back(s))
    ;

  if (fields.size() != 5U) {
    return osquery::Status(1, "Invalid platform version field");
  }

  version = fields[0] + "." + fields[2] + "." + fields[3];
  return osquery::Status(0, "OK");
}

osquery::Status getSMCVersion(std::string& version) {
  version.clear();

  auto smc_keys =
      osquery::SQL::selectAllFrom("smc_keys", "key", osquery::EQUALS, "RVBF");
  if (smc_keys.empty()) {
    return osquery::Status(1, "Failed to select the RVBF smc_keys row");
  }

  std::string raw_version_field = smc_keys[0]["value"];
  auto part0 = getSMCVersionField(raw_version_field, 0);
  auto part1 = getSMCVersionField(raw_version_field, 1);
  auto part2 = getSMCVersionField(raw_version_field, 2);
  auto part3 = getSMCVersionField(raw_version_field, 3);

  version = part0 + "." + part1 + part2 + part3;
  if (version.empty()) {
    return osquery::Status(1, "Failed to retrieve the smc version");
  }

  return osquery::Status(0, "OK");
}

osquery::Status getHardwareModel(std::string& model) {
  model.clear();

  auto mac_system_info = osquery::SQL::selectAllFrom("system_info");
  if (mac_system_info.empty()) {
    return osquery::Status(1, "Failed to list the system information");
  }

  model = mac_system_info[0]["hardware_model"];
  boost::trim(model);
  if (model.empty()) {
    return osquery::Status(1, "Failed to retrieve the hardware model");
  }

  return osquery::Status(0, "OK");
}

osquery::Status getOSVersion(std::string& version, std::string& build) {
  version.clear();
  build.clear();

  auto sw_vers = osquery::SQL::selectAllFrom(
      "plist",
      "path",
      osquery::EQUALS,
      "/System/Library/CoreServices/SystemVersion.plist");
  if (sw_vers.empty()) {
    return osquery::Status(1, "Failed to parse the SystemVersion plist file");
  }

  for (const auto& row : sw_vers) {
    if (row.at("key") == "ProductBuildVersion") {
      build = row.at("value");

    } else if (row.at("key") == "ProductVersion") {
      version = row.at("value");
    }
  }

  if (version.empty() || build.empty()) {
    return osquery::Status(
        1, "Failed to retrieve the OS version and build number");
  }

  return osquery::Status(0, "OK");
}

struct IORegistryEntryDeleter final {
  using pointer = io_registry_entry_t;

  void operator()(pointer p) {
    IOObjectRelease(p);
  }
};

struct CFStringRefDeleter final {
  using pointer = CFStringRef;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

osquery::Status getBoardID(std::string& board_id) {
  board_id.clear();

  std::unique_ptr<io_registry_entry_t, IORegistryEntryDeleter> registry;
  {
    io_registry_entry_t r = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));

    if (r == MACH_PORT_NULL) {
      return osquery::Status(
          1, "Failed to open the IOPlatformExpertDevice registry entry");
    }

    registry.reset(r);
  }

  std::unique_ptr<CFStringRef, CFStringRefDeleter> board_id_property;
  {
    CFStringRef p = static_cast<CFStringRef>(IORegistryEntryCreateCFProperty(
        registry.get(), CFSTR("board-id"), kCFAllocatorDefault, kNilOptions));

    if (p == nullptr || CFGetTypeID(p) != CFDataGetTypeID()) {
      return osquery::Status(1, "Failed to acquire the board-id property");
    }

    board_id_property.reset(p);
  }

  auto data_ref = reinterpret_cast<CFDataRef>(board_id_property.get());
  auto buffer = reinterpret_cast<const char*>(CFDataGetBytePtr(data_ref));

  board_id = buffer;
  if (board_id.find("Mac-") != 0) {
    auto status = osquery::Status(
        1, std::string("Unsupported logic board id: ") + board_id);

    board_id.clear();
    return status;
  }

  return osquery::Status(0, "OK");
}

osquery::Status getMACAddress(std::string& mac) {
  mac.clear();

  auto interface_details = osquery::SQL::selectAllFrom("interface_details");
  if (interface_details.empty()) {
    return osquery::Status(1, "Failed to list the network interfaces");
  }

  for (const auto& row : interface_details) {
    auto mac_address = row.at("mac");
    if (!mac_address.empty() && mac_address != "00:00:00:00:00:00") {
      mac = mac_address;
      break;
    }
  }

  if (mac.empty()) {
    return osquery::Status(1, "Failed to retrieve a valid mac address");
  }

  return osquery::Status(0, "OK");
}

osquery::Status getSystemInformation(SystemInformation& system_info) {
  auto status = getSMCVersion(system_info.smc_ver);
  if (!status.ok()) {
    return status;
  }

  status = getBoardID(system_info.board_id);
  if (!status.ok()) {
    return status;
  }

  status = getHardwareModel(system_info.hw_ver);
  if (!status.ok()) {
    return status;
  }

  status = getEFIVersion(system_info.rom_ver);
  if (!status.ok()) {
    return status;
  }

  osquery::getHostUUID(system_info.sys_uuid);
  if (system_info.sys_uuid.empty()) {
    return osquery::Status(1, "Failed to retrieve the system UUID");
  }

  status = getOSVersion(system_info.os_ver, system_info.build_num);
  if (!status.ok()) {
    return status;
  }

  status = getMACAddress(system_info.mac_addr);
  if (!status.ok()) {
    return status;
  }

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

  std::stringstream json_stream;
  pt::json_parser::write_json(json_stream, system_info_object);
  json = json_stream.str();

  return osquery::Status(0, "OK");
}

osquery::Status queryServer(ServerResponse& response,
                            const SystemInformation& system_info) {
  response = {};

  std::string request_data;
  auto status = getPostRequestData(request_data, system_info);
  if (!status.ok()) {
    return status;
  }

  osquery::http::Client::Options client_options;
  client_options.always_verify_peer(true)
      .openssl_options(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                       SSL_OP_NO_TLSv1_1)

      .openssl_certificate("/etc/ssl/cert.pem")
      .openssl_sni_hostname("api.efigy.io");

  client_options.timeout(5).follow_redirects(true);

  std::string raw_server_response;

  try {
    osquery::http::Request server_request("https://api.efigy.io/apple/oneshot");

    server_request << osquery::http::Request::Header("User-Agent", "osquery");
    server_request << osquery::http::Request::Header("Content-type",
                                                     "application/json");

    server_request << osquery::http::Request::Header("Accept",
                                                     "application/json");

    osquery::http::Client client(client_options);
    auto server_response = client.post(server_request, request_data);
    raw_server_response = server_response.body();

  } catch (const pt::json_parser_error& e) {
    return osquery::Status(
        1, std::string("Invalid JSON in server response: ") + e.what());

  } catch (const std::exception& e) {
    return osquery::Status(
        1, std::string("Could not query the EFIgy API endpoint: ") + e.what());
  }

  std::stringstream json_stream(raw_server_response);

  pt::ptree json_response;
  pt::read_json(json_stream, json_response);

  auto latest_efi_version =
      json_response.get_optional<std::string>("latest_efi_version.msg");

  if (!latest_efi_version || latest_efi_version->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_efi_version.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_efi_version.get());
  }

  auto latest_os_version =
      json_response.get_optional<std::string>("latest_os_version.msg");

  if (!latest_os_version || latest_os_version->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_os_version.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_os_version.get());
  }

  auto latest_build_number =
      json_response.get_optional<std::string>("latest_build_number.msg");

  if (!latest_build_number || latest_build_number->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_build_number.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_build_number.get());
  }

  response.latest_efi_version = latest_efi_version.get();
  response.latest_os_version = latest_os_version.get();
  response.latest_build_number = latest_build_number.get();

  return osquery::Status(0, "OK");
}
} // namespace

namespace osquery {
namespace tables {
QueryData queryEFIgy(QueryContext& context) {
  SystemInformation system_info;
  auto status = getSystemInformation(system_info);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();

    Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";

    return {r};
  }

  if (system_info.hw_ver.find("Mac") != 0) {
    VLOG(1) << "Unsupported hardware model: " << system_info.hw_ver;

    Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";

    return {r};
  }

  ServerResponse response;
  status = queryServer(response, system_info);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();

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
