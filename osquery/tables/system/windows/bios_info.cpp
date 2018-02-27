/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <osquery/tables.h>
#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {

const auto kHPBiosSettingRegex = boost::regex("\\*([\\w ]*)");
const std::vector<std::string> vHP = {
    "hp", "hewlett-packard", "hewlett packard"};
const std::vector<std::string> vLenovo = {"lenovo"};
const std::vector<std::string> vDell = {"dell inc."};
const std::map<std::string, std::pair<std::string, BSTR>> queryMap = {
    {"hp",
     {"select Name,Value from HP_BiosSetting", L"root\\hp\\instrumentedBIOS"}},
    {"lenovo", {"select CurrentSetting from Lenovo_BiosSetting", L"root\\wmi"}},
    {"dell",
     {"select AttributeName,CurrentValue,PossibleValues, "
      "PossibleValuesDescription from DCIM_BIOSEnumeration",
      L"root\\dcim\\sysman"}}};

std::string getManufacturer(std::string manufacturer) {
  transform(manufacturer.begin(),
            manufacturer.end(),
            manufacturer.begin(),
            ::tolower);

  if (std::find(vHP.begin(), vHP.end(), manufacturer) != vHP.end()) {
    manufacturer = "hp";
  } else if (std::find(vLenovo.begin(), vLenovo.end(), manufacturer) !=
             vLenovo.end()) {
    manufacturer = "lenovo";
  } else if (std::find(vDell.begin(), vDell.end(), manufacturer) !=
             vDell.end()) {
    manufacturer = "dell";
  }

  return manufacturer;
}

QueryData genBiosInfo(QueryContext& context) {
  QueryData results;
  std::string manufacturer;

  WmiRequest wmiComputerSystemReq(
      "select Manufacturer from Win32_ComputerSystem");
  std::vector<WmiResultItem>& wmiComputerSystemResults =
      wmiComputerSystemReq.results();

  if (!wmiComputerSystemResults.empty()) {
    wmiComputerSystemResults[0].GetString("Manufacturer", manufacturer);
    manufacturer = getManufacturer(manufacturer);
  } else {
    manufacturer = "N/A";
  }

  if (queryMap.find(manufacturer) != queryMap.end()) {
    WmiRequest wmiBiosReq(std::get<0>(queryMap.at(manufacturer)),
                          (std::get<1>(queryMap.at(manufacturer))));
    std::vector<WmiResultItem>& wmiResults = wmiBiosReq.results();

    for (unsigned int i = 0; i < wmiResults.size(); ++i) {
      Row r;

      if (manufacturer == "hp") {
        std::string value;
        boost::smatch matches;
        wmiResults[i].GetString("Name", r["Name"]);
        wmiResults[i].GetString("Value", value);

        if (boost::regex_search(value, matches, kHPBiosSettingRegex)) {
          r["Value"] = std::string(matches[1]);
        } else {
          r["Value"] = value;
        }

      } else if (manufacturer == "lenovo") {
        std::string currentSetting;
        std::vector<std::string> settings;
        wmiResults[i].GetString("CurrentSetting", currentSetting);
        settings = osquery::split(currentSetting, ",");

        if (settings.size() != 2) {
          continue;
        }
        r["Name"] = settings[0];
        r["Value"] = settings[1];

      } else if (manufacturer == "dell") {
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
      }

      results.push_back(r);
    }
  } else {
  	LOG(INFO) << "Vendor \"" << manufacturer << 
  							 "\" is currently not supported";
  }
  return results;
}
} // namespace tables
} // namespace osquery