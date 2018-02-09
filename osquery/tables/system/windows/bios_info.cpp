/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include "osquery/core/windows/wmi.h"
#include <osquery/tables.h>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include <string>

namespace osquery {
namespace tables {

const auto kHPBiosSettingRegex = boost::regex("\\*([\\w ]*)");

QueryData genBiosInfo(QueryContext& context) {
  QueryData results;
  std::string manufacturer;
  WmiRequest wmiComputerSystemReq(
      "select Manufacturer from Win32_ComputerSystem");
  std::vector<WmiResultItem>& wmiComputerSystemResults =
      wmiComputerSystemReq.results();
  wmiComputerSystemResults[0].GetString("Manufacturer", manufacturer);
  transform(manufacturer.begin(),
            manufacturer.end(),
            manufacturer.begin(),
            ::tolower);
  if ((manufacturer == "hp") || (manufacturer == "hewlett-packard") ||
      (manufacturer == "hewlett packard")) {
    WmiRequest wmiBiosReq("select Name,Value from HP_BiosSetting",
                          L"root\\hp\\instrumentedBIOS");
    std::vector<WmiResultItem>& wmiResults = wmiBiosReq.results();
    for (unsigned int i = 0; i < wmiResults.size(); ++i) {
      Row r;
      std::string value;
      boost::smatch matches;
      wmiResults[i].GetString("Name", r["Name"]);
      wmiResults[i].GetString("Value", value);
      if (boost::regex_search(value, matches, kHPBiosSettingRegex)) {
        r["Value"] = std::string(matches[1]);
      } else {
        r["Value"] = value;
      }
      results.push_back(r);
    }
  } else if (manufacturer == "lenovo") {
    std::string currentSetting;
    std::vector<std::string> settings;
    WmiRequest wmiBiosReq("select CurrentSetting from Lenovo_BiosSetting",
                          L"root\\wmi");
    std::vector<WmiResultItem>& wmiResults = wmiBiosReq.results();
    for (unsigned int i = 0; i < wmiResults.size(); ++i) {
      Row r;
      wmiResults[i].GetString("CurrentSetting", currentSetting);
      boost::split(settings,
                   currentSetting,
                   boost::is_any_of(","),
                   boost::token_compress_on);
      if (settings.size() != 2) {
        continue;
      }
      r["Name"] = settings[0];
      r["Value"] = settings[1];
      results.push_back(r);
    }
  } else if (manufacturer == "dell inc.") {
    // Using sysman from Dell Command Monitor
    WmiRequest wmiBiosReq(
        "select "
        "AttributeName,CurrentValue,PossibleValues, "
        "PossibleValuesDescription from DCIM_BIOSEnumeration ",
        L"root\\dcim\\sysman");
    std::vector<WmiResultItem>& wmiResults = wmiBiosReq.results();
    for (unsigned int i = 0; i < wmiResults.size(); ++i) {
      Row r;
      std::vector<std::string> vCurrentValue;
      std::vector<std::string> vPossibleValues;
      std::vector<std::string> vPossibleValuesDescription;
      wmiResults[i].GetString("AttributeName", r["Name"]);
      wmiResults[i].GetVectorOfStrings("CurrentValue", vCurrentValue);
      wmiResults[i].GetVectorOfStrings("PossibleValues", vPossibleValues);
      wmiResults[i].GetVectorOfStrings("PossibleValuesDescription",
                                       vPossibleValuesDescription);
      if (vCurrentValue.size() == 1 && !vPossibleValues.empty()) {
        auto pos = std::find(
            vPossibleValues.begin(), vPossibleValues.end(), vCurrentValue[0]);
        if (pos != vPossibleValues.end()) {
          r["Value"] =
              vPossibleValuesDescription[pos - vPossibleValues.begin()];
        } else {
          r["Value"] = "N/A";
        }
      } else if (vCurrentValue.size() > 1) {
        std::ostringstream oValueConcat;
        std::copy(vCurrentValue.begin(),
                  vCurrentValue.end() - 1,
                  std::ostream_iterator<std::string>(oValueConcat, ","));
        oValueConcat << vCurrentValue.back();

        r["Value"] = oValueConcat.str();
      } else {
        r["Value"] = "N/A";
      }
      results.push_back(r);
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
