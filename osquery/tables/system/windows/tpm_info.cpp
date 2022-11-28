/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>

namespace osquery::tables {

namespace {

const std::string kWin32TpmQuery{"SELECT * FROM Win32_Tpm"};
const std::wstring kTpmClassNamespace{L"root\\cimv2\\Security\\MicrosoftTpm"};

const std::unordered_map<std::string, std::string> kBooleanMethodList{
    {"IsActivated", "activated"},
    {"IsEnabled", "enabled"},
    {"IsOwned", "owned"}};

const std::unordered_map<std::string, std::string> kStringPropertyList{
    {"ManufacturerIdTxt", "manufacturer_name"},
    {"ManufacturerVersion", "manufacturer_version"},
    {"ManufacturerVersionInfo", "product_name"},
    {"PhysicalPresenceVersionInfo", "physical_presence_version"},
    {"SpecVersion", "spec_version"}};

} // namespace

QueryData genTpmInfo(QueryContext& context) {
  BSTR class_namespace = ::SysAllocString(kTpmClassNamespace.c_str());
  if (class_namespace == nullptr) {
    LOG(ERROR) << "tpm_info: Failed to allocate the WMI class namespace string";
    return {};
  }

  auto exp_wmi_request =
      WmiRequest::CreateWmiRequest(kWin32TpmQuery, class_namespace);
  ::SysFreeString(class_namespace);

  if (exp_wmi_request.isError()) {
    const auto& error = exp_wmi_request.getError();

    LOG(ERROR) << "tpm_info: The following WMI query could not be constructed: "
               << class_namespace << ":" << kWin32TpmQuery << ". "
               << error.getMessage();

    return {};
  }

  auto wmi_request = exp_wmi_request.take();
  if (!wmi_request.getStatus().ok()) {
    LOG(ERROR) << "tpm_info: The following WMI query has failed: "
               << kWin32TpmQuery;

    return {};
  }

  const auto& wmi_item_list = wmi_request.results();
  if (wmi_item_list.empty()) {
    LOG(ERROR) << "tpm_info: The following WMI query did not return any item: "
               << kWin32TpmQuery;

    return {};
  }

  if (wmi_item_list.size() != 1) {
    LOG(ERROR) << "tpm_info: The following WMI query returned an "
                  "unexpected number of items: "
               << kWin32TpmQuery << ". Only the first result will be returned";
  }

  const auto& wmi_item = wmi_item_list.back();

  Row row = {};

  long manufacturer_id{};
  auto status = wmi_item.GetLong("ManufacturerId", manufacturer_id);
  if (!status.ok()) {
    LOG(ERROR) << "tpm_info: Failed to acquire the ManufacturerId WMI property";

    manufacturer_id = -1;
  }

  row["manufacturer_id"] = INTEGER(manufacturer_id);

  for (const auto& p : kStringPropertyList) {
    const auto& property_name = p.first;
    const auto& column_name = p.second;

    std::string string_buffer;
    status = wmi_item.GetString(property_name, string_buffer);
    if (!status.ok()) {
      LOG(ERROR) << "tpm_info: Failed to acquire the " << property_name
                 << " WMI property";

      string_buffer.clear();
    }

    row[column_name] = SQL_TEXT(string_buffer);
  }

  for (const auto& p : kBooleanMethodList) {
    const auto& method_name = p.first;
    const auto& column_name = p.second;

    int value{};

    {
      WmiResultItem method_result;
      status = wmi_request.ExecMethod(wmi_item, method_name, {}, method_result);
      if (status.ok()) {
        bool boolean_value{};
        status = method_result.GetBool(method_name, boolean_value);
        if (!status.ok()) {
          LOG(ERROR)
              << "tpm_info: Failed to read the output of the following method: "
              << method_name;

          boolean_value = false;
        }

        value = boolean_value ? 1 : 0;

      } else {
        LOG(ERROR) << "tpm_info: Failed to execute the following method: "
                   << method_name;
        value = 0;
      }
    }

    row[column_name] = INTEGER(value);
  }

  return {row};
}

} // namespace osquery::tables
