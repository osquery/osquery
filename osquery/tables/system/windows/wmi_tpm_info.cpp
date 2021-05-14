/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>

namespace osquery {
namespace tables {

QueryData genTpmInfo(QueryContext& context) {
  QueryData resultsdata;
  std::stringstream ss;
  ss << "SELECT * FROM Win32_Tpm";

  BSTR bstr = ::SysAllocString(L"root\\cimv2\\Security\\MicrosoftTpm");
  const WmiRequest request(ss.str(), bstr);
  ::SysFreeString(bstr);

  if (request.getStatus().ok()) {
    const auto& results = request.results();
    for (const auto& result : results) {
      Row r;

      auto isBool = false;
      long ManufacturerID;

      result.GetBool("IsActivated_InitialValue", isBool);
      r["is_activated_initialvalue"] = isBool ? "True" : "False";
      result.GetBool("IsEnabled_InitialValue", isBool);
      r["is_enabled_initialvalue"] = isBool ? "True" : "False";
      result.GetBool("IsOwned_InitialValue", isBool);
      r["is_owned_initialvalue"] = isBool ? "True" : "False";
      (result.GetLong("ManufacturerId", ManufacturerID))
          ? r["manufacturer_id"] = INTEGER(ManufacturerID)
          : r["manufacturer_id"] = "-1";
      result.GetString("ManufacturerIdTxt", r["manufacturer_id_txt"]);
      result.GetString("ManufacturerVersion", r["manufacturer_version"]);
      result.GetString("ManufacturerVersionFull20",
                       r["manufacturer_version_full"]);
      result.GetString("ManufacturerVersionInfo",
                       r["manufacturer_version_info"]);
      result.GetString("PhysicalPresenceVersionInfo",
                       r["physical_presence_version_info"]);
      result.GetString("SpecVersion", r["spec_version"]);
      result.GetString("PSComputerName", r["ps_computer_name"]);
      resultsdata.push_back(r);
    }
  }

  return resultsdata;
}
} // namespace tables
} // namespace osquery
