/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

#include <osquery/core/windows/wmi.h>

namespace osquery {
namespace tables {

const auto kHPBiosSettingRegex = std::regex("\\*([\\w ]*)");
const std::vector<std::string> kHP = {
    "hp", "hewlett-packard", "hewlett packard"};
const std::vector<std::string> kLenovo = {"lenovo"};
const std::vector<std::string> kDell = {"dell inc."};
const std::map<std::string, std::pair<std::string, std::wstring>> kQueryMap = {
    {"hp",
     {"select Name,Value from HP_BiosSetting", L"root\\hp\\instrumentedBIOS"}},
    {"lenovo", {"select CurrentSetting from Lenovo_BiosSetting", L"root\\wmi"}},
    // Dell machines have two different wmi classes for bios information.
    // Biosattributes class is present on all machines released after 2018 and
    // DCIM_BIOSEnumeration is on the machines released prior to 2018 or have
    // Dell Command Monitor driver installed on them.
    {"dell",
     {"select AttributeName,CurrentValue from EnumerationAttribute",
      L"root\\dcim\\sysman\\biosattributes"}},
    {"dell-legacy",
     {"select AttributeName,CurrentValue,PossibleValues, "
      "PossibleValuesDescription from DCIM_BIOSEnumeration",
      L"root\\dcim\\sysman"}}};

std::string getManufacturer(std::string manufacturer) {
  transform(manufacturer.begin(),
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
    auto it = kQueryMap.find("dell-legacy");
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

QueryData genBiosInfo(QueryContext& context) {
  const auto wmiComputerSystemReq = WmiRequest::CreateWmiRequest(
      "select Manufacturer from Win32_ComputerSystem");
  if (!wmiComputerSystemReq || wmiComputerSystemReq->results().empty()) {
    return {};
  }
  const auto& wmiComputerSystemResults = wmiComputerSystemReq->results();

  std::string manufacturer;
  wmiComputerSystemResults[0].GetString("Manufacturer", manufacturer);
  manufacturer = getManufacturer(manufacturer);

  auto it = kQueryMap.find(manufacturer);
  if (it == kQueryMap.end()) {
    LOG(INFO) << "Vendor \"" << manufacturer << "\" is currently not supported";
    return {};
  }

  QueryData results;
  const auto wmiBiosReq = WmiRequest::CreateWmiRequest(std::get<0>(it->second),
                                                       std::get<1>(it->second));
  if (!wmiBiosReq) {
    LOG(WARNING) << wmiBiosReq.getError().getMessage();
    return results;
  }
  const auto& wmiResults = wmiBiosReq->results();
  for (size_t i = 0; i < wmiResults.size(); ++i) {
    Row r;
    if (manufacturer == "hp") {
      r = getHPBiosInfo(wmiResults[i]);

    } else if (manufacturer == "lenovo") {
      r = getLenovoBiosInfo(wmiResults[i]);

    } else if (manufacturer == "dell") {
      r = getDellBiosInfo(wmiResults[i]);

    } else if (manufacturer == "dell-legacy") {
      r = getDellLegacyBiosInfo(wmiResults[i]);
    }
    if (!r.empty()) {
      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
