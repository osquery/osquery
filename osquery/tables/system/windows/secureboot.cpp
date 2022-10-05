/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/info/firmware.h>

#include <Windows.h>

namespace osquery::tables {

namespace {

boost::optional<bool> readFirmwareBooleanVariable(
    std::string namespace_guid, const std::string& variable_name) {
  namespace_guid = "{" + namespace_guid + "}";

  std::array<std::uint8_t, 2> read_buffer;
  auto bytes_read =
      GetFirmwareEnvironmentVariableA(variable_name.c_str(),
                                      namespace_guid.c_str(),
                                      read_buffer.data(),
                                      static_cast<DWORD>(read_buffer.size()));

  if (bytes_read == 0) {
    auto error = GetLastError();
    LOG(ERROR) << "secureboot: Unable to get EFI variable " << namespace_guid
               << "::" << variable_name
               << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  if (bytes_read != 1) {
    auto error = GetLastError();
    LOG(ERROR)
        << "secureboot: The following EFI variable has an unexpected size: "
        << namespace_guid << "::" << variable_name
        << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  const auto& value = read_buffer[0];
  if (value > 1) {
    auto error = GetLastError();
    LOG(ERROR) << "secureboot: The following EFI variable is not a boolean: "
               << namespace_guid << "::" << variable_name
               << ". Value: " << static_cast<std::uint32_t>(value)
               << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  return (value == 1);
}

bool enableSystemEnvironmentNamePrivilege() {
  TOKEN_PRIVILEGES token_privileges{};
  token_privileges.PrivilegeCount = 1;

  if (!LookupPrivilegeValueW(nullptr,
                             L"SeSystemEnvironmentPrivilege",
                             &token_privileges.Privileges[0].Luid)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to lookup the required privilege: "
               << errorDwordToString(error_code);

    return false;
  }

  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  HANDLE process_token{INVALID_HANDLE_VALUE};
  if (OpenProcessToken(
          GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &process_token) == 0) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to open the process token: "
               << errorDwordToString(error_code);

    return false;
  }

  if (!AdjustTokenPrivileges(process_token,
                             FALSE,
                             &token_privileges,
                             sizeof(TOKEN_PRIVILEGES),
                             nullptr,
                             nullptr)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to adjust token privileges: "
               << errorDwordToString(error_code);

    return false;
  }

  auto error_code = GetLastError();
  if (error_code == ERROR_NOT_ALL_ASSIGNED) {
    LOG(ERROR) << "secureboot: Failed to adjust token privileges: "
               << errorDwordToString(error_code);
    return false;
  }

  return true;
}

} // namespace

QueryData genSecureBoot(QueryContext& context) {
  static const auto kPrivilegeInitializationStatus{
      enableSystemEnvironmentNamePrivilege()};

  static const std::unordered_map<std::string,
                                  std::pair<std::string, std::string>>
      kRequestMap{
          {"secure_boot", std::make_pair(kEFIBootGUID, kEFISecureBootName)},
          {"setup_mode", std::make_pair(kEFIBootGUID, kEFISetupModeName)},
      };

  auto opt_firmware_kind = getFirmwareKind();
  if (!opt_firmware_kind.has_value()) {
    LOG(ERROR) << "secureboot: Failed to determine the firmware type";
    return {};
  }

  const auto& firmware_kind = opt_firmware_kind.value();
  if (firmware_kind != FirmwareKind::Uefi) {
    VLOG(1) << "secureboot: Secure boot is only supported on UEFI firmware";
    return {};
  }

  if (!kPrivilegeInitializationStatus) {
    LOG(ERROR) << "secureboot: The SE_SYSTEM_ENVIRONMENT_NAME privilege could "
                  "not be acquired. Table data may be wrong";
  }

  Row row;
  for (const auto& p : kRequestMap) {
    const auto& column_name = p.first;
    const auto& namespace_and_variable = p.second;

    const auto& namespace_guid = namespace_and_variable.first;
    const auto& variable_name = namespace_and_variable.second;

    auto opt_value = readFirmwareBooleanVariable(namespace_guid, variable_name);
    if (opt_value.has_value()) {
      row[column_name] = INTEGER(opt_value.value() ? 1 : 0);
    } else {
      row[column_name] = INTEGER(-1);
    }
  }

  return {std::move(row)};
}

} // namespace osquery::tables
