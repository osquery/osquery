/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <iomanip>
#include <map>
#include <regex>
#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {
namespace tables {

const auto kHPBiosSettingRegex = std::regex("\\*([\\w ]*)");
const std::vector<std::string> kHP = {
    "hp", "hewlett-packard", "hewlett packard"};
const std::vector<std::string> kLenovo = {"lenovo"};
const std::vector<std::string> kDell = {"dell inc."};
const std::map<std::string, std::pair<std::string, std::wstring>>
    kVendorSpecificQueryMap = {
        {"hp",
         {"select Name,Value from HP_BiosSetting",
          L"root\\hp\\instrumentedBIOS"}},
        {"lenovo",
         {"select CurrentSetting from Lenovo_BiosSetting", L"root\\wmi"}},
        // Dell machines have two different wmi classes for bios information.
        // Biosattributes class is present on all machines released after 2018
        // and DCIM_BIOSEnumeration is on the machines released prior to 2018 or
        // have Dell Command Monitor driver installed on them.
        {"dell",
         {"select AttributeName,CurrentValue from EnumerationAttribute",
          L"root\\dcim\\sysman\\biosattributes"}},
        {"dell-legacy",
         {"select AttributeName,CurrentValue,PossibleValues, "
          "PossibleValuesDescription from DCIM_BIOSEnumeration",
          L"root\\dcim\\sysman"}}};

std::string getManufacturer(std::string manufacturer) {
  std::transform(manufacturer.begin(),
                 manufacturer.end(),
                 manufacturer.begin(),
                 ::tolower);

  if (std::find(kHP.begin(), kHP.end(), manufacturer) != kHP.end()) {
    manufacturer = "hp";
  } else if (std::find(kLenovo.begin(), kLenovo.end(), manufacturer) !=
             kLenovo.end()) {
    manufacturer = "lenovo";
  } else if (std::find(kDell.begin(), kDell.end(), manufacturer) !=
             kDell.end()) {
    // If it's a Dell machine, we check if the legacy class exists or not and
    // accordingly return the corresponding manufacturer name.
    auto it = kVendorSpecificQueryMap.find("dell-legacy");
    const auto wmiBiosReq = WmiRequest::CreateWmiRequest(
        std::get<0>(it->second), std::get<1>(it->second));
    if (wmiBiosReq && !wmiBiosReq->results().empty()) {
      manufacturer = "dell-legacy";
    } else {
      manufacturer = "dell";
    }
  }

  return manufacturer;
}

Row getHPBiosInfo(const WmiResultItem& item) {
  Row r;

  std::string value;
  std::smatch matches;
  item.GetString("Name", r["name"]);
  item.GetString("Value", value);

  if (std::regex_search(value, matches, kHPBiosSettingRegex)) {
    r["value"] = std::string(matches[1]);
  } else {
    r["value"] = value;
  }

  return r;
}

Row getLenovoBiosInfo(const WmiResultItem& item) {
  Row r;

  std::string currentSetting;
  std::vector<std::string> settings;
  item.GetString("CurrentSetting", currentSetting);
  settings = osquery::split(currentSetting, ",");

  if (settings.size() != 2) {
    return r;
  }
  r["name"] = settings[0];
  r["value"] = settings[1];

  return r;
}

Row getDellLegacyBiosInfo(const WmiResultItem& item) {
  Row r;

  std::vector<std::string> vCurrentValue;
  std::vector<std::string> vPossibleValues;
  std::vector<std::string> vPossibleValuesDescription;
  item.GetString("AttributeName", r["name"]);
  item.GetVectorOfStrings("CurrentValue", vCurrentValue);
  item.GetVectorOfStrings("PossibleValues", vPossibleValues);
  item.GetVectorOfStrings("PossibleValuesDescription",
                          vPossibleValuesDescription);

  if (vCurrentValue.size() == 1 && !vPossibleValues.empty()) {
    auto pos = std::find(
        vPossibleValues.begin(), vPossibleValues.end(), vCurrentValue[0]);
    if (pos != vPossibleValues.end()) {
      r["value"] = vPossibleValuesDescription[pos - vPossibleValues.begin()];
    } else {
      r["value"] = "N/A";
    }

  } else if (vCurrentValue.size() > 1) {
    std::ostringstream oValueConcat;
    std::copy(vCurrentValue.begin(),
              vCurrentValue.end() - 1,
              std::ostream_iterator<std::string>(oValueConcat, ","));
    oValueConcat << vCurrentValue.back();

    r["value"] = oValueConcat.str();

  } else {
    r["value"] = "N/A";
  }

  return r;
}

Row getDellBiosInfo(const WmiResultItem& item) {
  Row r;

  std::string currentvalue;
  item.GetString("AttributeName", r["name"]);
  item.GetString("CurrentValue", currentvalue);
  if (currentvalue.empty()) {
    r["value"] = "N/A";
  } else {
    r["value"] = currentvalue;
  }
  return r;
}

QueryData generateCommonBiosRows() {
  static const std::string kWin32BiosQuery{
      "SELECT *, BiosCharacteristics, BIOSVersion, BuildNumber, Caption, "
      "CodeSet, CurrentLanguage, Description, EmbeddedControllerMajorVersion, "
      "EmbeddedControllerMinorVersion, IdentificationCode, "
      "InstallableLanguages, InstallDate, LanguageEdition, ListOfLanguages, "
      "Manufacturer, Name, OtherTargetOS, PrimaryBIOS, ReleaseDate, "
      "SerialNumber, SMBIOSBIOSVersion, SMBIOSMajorVersion, "
      "SMBIOSMinorVersion, SMBIOSPresent, SoftwareElementID, "
      "SoftwareElementState, Status, SystemBiosMajorVersion, "
      "SystemBiosMinorVersion, TargetOperatingSystem, Version FROM Win32_BIOS"};

  static const std::vector<std::string> kStringKeyNameList{"BuildNumber",
                                                           "Caption",
                                                           "CodeSet",
                                                           "CurrentLanguage",
                                                           "Description",
                                                           "IdentificationCode",
                                                           "LanguageEdition",
                                                           "Manufacturer",
                                                           "Name",
                                                           "OtherTargetOS",
                                                           "SerialNumber",
                                                           "SMBIOSBIOSVersion",
                                                           "SoftwareElementID",
                                                           "Status",
                                                           "Version"};

  static const std::vector<std::string> kStringVectorKeyNameList{
      "BIOSVersion", "ListOfLanguages"};

  static const std::vector<std::string> kUInt16KeyNameList{
      "InstallableLanguages",
      "SMBIOSMajorVersion",
      "SMBIOSMinorVersion",
      "SoftwareElementState",
      "TargetOperatingSystem"};

  static const std::vector<std::string> kUInt16VectorKeyNameList{
      "BiosCharacteristics"};

  static const std::vector<std::string> kUInt8KeyNameList{
      "SystemBiosMajorVersion",
      "SystemBiosMinorVersion",
      "EmbeddedControllerMajorVersion",
      "EmbeddedControllerMinorVersion"};

  static const std::vector<std::string> kBooleanKeyNameList{"PrimaryBIOS",
                                                            "SMBIOSPresent"};

  static const std::vector<std::string> kDateKeyNameList{"InstallDate",
                                                         "ReleaseDate"};

  auto exp_wmi_request = WmiRequest::CreateWmiRequest(kWin32BiosQuery);
  if (exp_wmi_request.isError()) {
    const auto& error = exp_wmi_request.getError();

    LOG(ERROR)
        << "wmi_bios_info: The following WMI query could not be constructed: "
        << kWin32BiosQuery << ". " << error.getMessage();

    return {};
  }

  auto wmi_request = exp_wmi_request.take();
  if (!wmi_request.getStatus().ok()) {
    LOG(ERROR) << "wmi_bios_info: The following WMI query has failed: "
               << kWin32BiosQuery;
    return {};
  }

  const auto& wmi_item_list = wmi_request.results();
  if (wmi_item_list.empty()) {
    LOG(ERROR)
        << "wmi_bios_info: The following WMI query did not return any item: "
        << kWin32BiosQuery;
    return {};
  }

  if (wmi_item_list.size() != 1) {
    LOG(ERROR) << "wmi_bios_info: The following WMI query returned an "
                  "unexpected number of items: "
               << kWin32BiosQuery;
  }

  const auto& wmi_item = wmi_item_list.back();

  QueryData row_list;
  auto L_generateRow = [&row_list](std::string key, std::string value) {
    Row row{};
    row["name"] = std::move(key);
    row["value"] = std::move(value);

    row_list.push_back(std::move(row));
  };

  for (const auto& key_name : kStringKeyNameList) {
    std::string value;
    auto status = wmi_item.GetString(key_name, value);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;

      value.clear();
    }

    L_generateRow(key_name, std::move(value));
  }

  for (const auto& key_name : kStringVectorKeyNameList) {
    std::vector<std::string> value_list;
    auto status = wmi_item.GetVectorOfStrings(key_name, value_list);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;

      value_list.clear();
    }

    std::string buffer = "{";
    for (const auto& value : value_list) {
      if (buffer.size() > 1) {
        buffer += ", ";
      }

      buffer += value;
    }

    buffer += "}";

    L_generateRow(key_name, std::move(buffer));
  }

  for (const auto& key_name : kUInt16KeyNameList) {
    long value{};
    auto status = wmi_item.GetLong(key_name, value);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;
      value = 0;
    }

    L_generateRow(key_name, std::to_string(value));
  }

  for (const auto& key_name : kUInt16VectorKeyNameList) {
    std::vector<long> value_list;
    auto status = wmi_item.GetVectorOfLongs(key_name, value_list);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;
      value_list.clear();
    }

    std::string buffer = "{";
    for (const auto& value : value_list) {
      if (buffer.size() > 1) {
        buffer += ", ";
      }

      buffer += std::to_string(value);
    }

    buffer += "}";

    L_generateRow(key_name, std::move(buffer));
  }

  for (const auto& key_name : kUInt8KeyNameList) {
    unsigned char value{};
    auto status = wmi_item.GetUChar(key_name, value);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;
      value = 0;
    }

    L_generateRow(key_name, std::to_string(value));
  }

  for (const auto& key_name : kBooleanKeyNameList) {
    bool value{};
    auto status = wmi_item.GetBool(key_name, value);
    if (!status.ok()) {
      VLOG(1) << "wmi_bios_info: Failed to copy the following Win32_BIOS WMI "
                 "column value: "
              << key_name;
      value = false;
    }

    L_generateRow(key_name, value ? "true" : "false");
  }

  for (const auto& key_name : kDateKeyNameList) {
    std::uint64_t timestamp{};

    {
      FILETIME value{};
      auto status = wmi_item.GetDateTime(key_name, false, value);
      if (status.ok()) {
        timestamp = static_cast<std::uint64_t>(filetimeToUnixtime(value));

      } else {
        VLOG(1)
            << "wmi_bios_info: Failed to acquire the following column value: "
            << key_name << ". " << status.getMessage();
      }
    }

    L_generateRow(key_name, std::to_string(timestamp));
  }

  return row_list;
}

QueryData genBiosInfo(QueryContext& context) {
  static const std::string kWin32ComputerSystemQuery{
      "select Manufacturer from Win32_ComputerSystem"};

  auto row_list = generateCommonBiosRows();

  std::string manufacturer;

  {
    auto exp_wmi_request =
        WmiRequest::CreateWmiRequest(kWin32ComputerSystemQuery);
    if (exp_wmi_request.isError()) {
      const auto& error = exp_wmi_request.getError();
      LOG(ERROR) << "wmi_bios_info: The WMI query has failed: "
                 << error.getMessage();

      return row_list;
    }

    auto wmi_request = exp_wmi_request.take();

    const auto& wmi_item_list = wmi_request.results();
    if (wmi_item_list.size() != 1) {
      LOG(ERROR) << "wmi_bios_info: Too many items returned when trying to "
                    "query for the the "
                    "manufacturer";
      return row_list;
    }

    const auto& first_wmi_item = wmi_item_list.back();
    if (!first_wmi_item.GetString("Manufacturer", manufacturer)) {
      LOG(ERROR) << "wmi_bios_info: Failed to read the bios manufacturer";
      return row_list;
    }

    manufacturer = getManufacturer(manufacturer);
  }

  auto vendor_specific_query_it = kVendorSpecificQueryMap.find(manufacturer);
  if (vendor_specific_query_it == kVendorSpecificQueryMap.end()) {
    return row_list;
  }

  const auto& wmi_query = std::get<0>(vendor_specific_query_it->second);
  const auto& wmi_namespace = std::get<1>(vendor_specific_query_it->second);

  auto exp_wmi_request = WmiRequest::CreateWmiRequest(wmi_query, wmi_namespace);
  if (exp_wmi_request.isError()) {
    const auto& error = exp_wmi_request.getError();
    LOG(ERROR) << "wmi_bios_info: The following WMI query has failed: "
               << wmi_query << " (namespace: " << wstringToString(wmi_namespace)
               << "). " << error.getMessage();

    return row_list;
  }

  auto wmi_request = exp_wmi_request.take();

  const auto& wmi_item_list = wmi_request.results();

  for (const auto& wmi_item : wmi_item_list) {
    Row r{};
    if (manufacturer == "hp") {
      r = getHPBiosInfo(wmi_item);

    } else if (manufacturer == "lenovo") {
      r = getLenovoBiosInfo(wmi_item);

    } else if (manufacturer == "dell") {
      r = getDellBiosInfo(wmi_item);

    } else if (manufacturer == "dell-legacy") {
      r = getDellLegacyBiosInfo(wmi_item);
    }

    if (!r.empty()) {
      row_list.push_back(r);
    }
  }

  return row_list;
}
} // namespace tables
} // namespace osquery
