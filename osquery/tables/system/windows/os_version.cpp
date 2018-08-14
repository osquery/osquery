/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

const std::map<DWORD, std::string> kOsVersion = {
    {PRODUCT_BUSINESS, "Business"},
    {PRODUCT_BUSINESS_N, "Business N"},
    {PRODUCT_CLUSTER_SERVER, "HPC Edition"},
    {PRODUCT_CLUSTER_SERVER_V, "Server Hyper Core V"},
    {PRODUCT_CORE, "Windows 10 Home"},
    {PRODUCT_CORE_COUNTRYSPECIFIC, "Windows 10 Home China"},
    {PRODUCT_CORE_N, "Windows 10 Home N"},
    {PRODUCT_CORE_SINGLELANGUAGE, "Windows 10 Home Single Language"},
    {PRODUCT_DATACENTER_EVALUATION_SERVER,
     "Server Datacenter (evaluation installation)"},
    {PRODUCT_DATACENTER_SERVER, "Server Datacenter (full installation)"},
    {PRODUCT_DATACENTER_SERVER_CORE, "Server Datacenter (core installation)"},
    {PRODUCT_DATACENTER_SERVER_V,
     "Server Datacenter without Hyper-V (full installation)"},
    {PRODUCT_ENTERPRISE, "Windows 10 Enterprise"},
    {PRODUCT_ENTERPRISE_E, "Windows 10 Enterprise E"},
    {PRODUCT_ENTERPRISE_EVALUATION, "Windows 10 Enterprise Evaluation"},
    {PRODUCT_ENTERPRISE_N, "Windows 10 Enterprise N"},
    {PRODUCT_ENTERPRISE_N_EVALUATION, "Windows 10 Enterprise N Evaluation"},
    {PRODUCT_ENTERPRISE_SERVER, "Server Enterprise (full installation)"},
    {PRODUCT_ENTERPRISE_SERVER_CORE, "Server Enterprise (core installation)"},
    {PRODUCT_ENTERPRISE_SERVER_CORE_V,
     "Server Enterprise without Hyper-V (core installation)"},
    {PRODUCT_ENTERPRISE_SERVER_IA64,
     "Server Enterprise for Itanium-based Systems"},
    {PRODUCT_ENTERPRISE_SERVER_V,
     "Server Enterprise without Hyper-V (full installation)"},
    {PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL,
     "Windows Essential Server Solution Additional"},
    {PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC,
     "Windows Essential Server Solution Additional SVC"},
    {PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT,
     "Windows Essential Server Solution Management"},
    {PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC,
     "Windows Essential Server Solution Management SVC"},
    {PRODUCT_HOME_BASIC, "Home Basic"},
    {PRODUCT_HOME_BASIC_E, "Not supported"},
    {PRODUCT_HOME_BASIC_N, "Home Basic N"},
    {PRODUCT_HOME_PREMIUM, "Home Premium"},
    {PRODUCT_HOME_PREMIUM_E, "Not supported"},
    {PRODUCT_HOME_PREMIUM_N, "Home Premium N"},
    {PRODUCT_HOME_PREMIUM_SERVER, "Windows Home Server 2011"},
    {PRODUCT_HOME_SERVER, "Windows Storage Server 2008 R2 Essentials"},
    {PRODUCT_HYPERV, "Microsoft Hyper-V Server"},
    {PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT,
     "Windows Essential Business Server Management Server"},
    {PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING,
     "Windows Essential Business Server Messaging Server"},
    {PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY,
     "Windows Essential Business Server Security Server"},
    {PRODUCT_MULTIPOINT_PREMIUM_SERVER,
     "Windows MultiPoint Server Premium (full installation)"},
    {PRODUCT_MULTIPOINT_STANDARD_SERVER,
     "Windows MultiPoint Server Standard (full installation)"},
    {PRODUCT_PROFESSIONAL, "Windows 10 Pro"},
    {PRODUCT_PROFESSIONAL_E, "Not supported"},
    {PRODUCT_PROFESSIONAL_N, "Windows 10 Pro N"},
    {PRODUCT_PROFESSIONAL_WMC, "Professional with Media Center"},
    {PRODUCT_SB_SOLUTION_SERVER,
     "Windows Small Business Server 2011 Essentials"},
    {PRODUCT_SB_SOLUTION_SERVER_EM, "Server For SB Solutions EM"},
    {PRODUCT_SERVER_FOR_SB_SOLUTIONS, "Server For SB Solutions"},
    {PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM, "Server For SB Solutions EM"},
    {PRODUCT_SERVER_FOR_SMALLBUSINESS,
     "Windows Server 2008 for Windows Essential Server Solutions"},
    {PRODUCT_SERVER_FOR_SMALLBUSINESS_V,
     "Windows Server 2008 without Hyper-V for Windows Essential Server "
     "Solutions"},
    {PRODUCT_SERVER_FOUNDATION, "Server Foundation"},
    {PRODUCT_SMALLBUSINESS_SERVER, "Windows Small Business Server"},
    {PRODUCT_SMALLBUSINESS_SERVER_PREMIUM, "Small Business Server Premium"},
    {PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE,
     "Small Business Server Premium (core installation)"},
    {PRODUCT_SOLUTION_EMBEDDEDSERVER, "Windows MultiPoint Server"},
    {PRODUCT_STANDARD_EVALUATION_SERVER,
     "Server Standard (evaluation installation)"},
    {PRODUCT_STANDARD_SERVER, "Server Standard"},
    {PRODUCT_STANDARD_SERVER_CORE, "Server Standard (core installation)"},
    {PRODUCT_STANDARD_SERVER_CORE_V,
     "Server Standard without Hyper-V (core installation)"},
    {PRODUCT_STANDARD_SERVER_V, "Server Standard without Hyper-V"},
    {PRODUCT_STANDARD_SERVER_SOLUTIONS, "Server Solutions Premium"},
    {PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE,
     "Server Solutions Premium (core installation)"},
    {PRODUCT_STARTER, "Starter"},
    {PRODUCT_STARTER_E, "Not supported"},
    {PRODUCT_STARTER_N, "Starter N"},
    {PRODUCT_STORAGE_ENTERPRISE_SERVER, "Storage Server Enterprise"},
    {PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE,
     "Storage Server Enterprise (core installation)"},
    {PRODUCT_STORAGE_EXPRESS_SERVER, "Storage Server Express"},
    {PRODUCT_STORAGE_EXPRESS_SERVER_CORE,
     "Storage Server Express (core installation)"},
    {PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER,
     "Storage Server Standard (evaluation installation)"},
    {PRODUCT_STORAGE_STANDARD_SERVER, "Storage Server Standard"},
    {PRODUCT_STORAGE_STANDARD_SERVER_CORE,
     "Storage Server Standard (core installation)"},
    {PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER,
     "Storage Server Workgroup (evaluation installation)"},
    {PRODUCT_STORAGE_WORKGROUP_SERVER, "Storage Server Workgroup"},
    {PRODUCT_STORAGE_WORKGROUP_SERVER_CORE,
     "Storage Server Workgroup (core installation)"},
    {PRODUCT_ULTIMATE, "Ultimate"},
    {PRODUCT_ULTIMATE_E, "Not supported"},
    {PRODUCT_ULTIMATE_N, "Ultimate N"},
    {PRODUCT_UNDEFINED, "An unknown product"},
    {PRODUCT_WEB_SERVER, "Web Server (full installation)"},
    {PRODUCT_WEB_SERVER_CORE, "Web Server (core installation)"}};

QueryData genOSVersion(QueryContext& context) {
  Row r;
  std::string version_string;

  const std::string kWmiQuery =
      "SELECT CAPTION,VERSION FROM Win32_OperatingSystem";

  const WmiRequest wmiRequest(kWmiQuery);
  const std::vector<WmiResultItem>& wmiResults = wmiRequest.results();

  if (wmiResults.empty()) {
    return {};
  }

  wmiResults[0].GetString("Caption", r["name"]);
  wmiResults[0].GetString("Version", version_string);
  auto version = osquery::split(version_string, ".");

  switch (version.size()) {
  case 3:
    r["build"] = SQL_TEXT(version[2]);
  case 2:
    r["minor"] = INTEGER(version[1]);
  case 1:
    r["major"] = INTEGER(version[0]);
    break;
  default:
    break;
  }

  r["platform"] = "windows";
  r["platform_like"] = "windows";
  r["version"] = r["major"] + "." + r["minor"] + "." + r["build"];
  if (version.size() >= 2) {
    auto prodType = 0;
    long const majorVersion = tryTo<long>(version[0], 10).takeOr(0l);
    long const minorVersion = tryTo<long>(version[1], 10).takeOr(0l);

    GetProductInfo(
        majorVersion, minorVersion, 0, 0, reinterpret_cast<DWORD*>(&prodType));
    if (kOsVersion.count(prodType) > 0) {
      r["codename"] = kOsVersion.at(prodType);
    }
  }

  return {r};
}
}
}
