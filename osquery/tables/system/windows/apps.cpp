/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>
#include <sstream>

#include <stdlib.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

void queryReg(QueryData& results_data) {
	QueryData regResults;
	queryKey("HKEY_LOCAL_MACHINE", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", regResults);
	for (const auto& rKey : regResults) {
		QueryData appResults;
		std::string subkey = rKey.at("subkey");
		// make sure it's a sane uninstall key
		boost::smatch matches;
		boost::regex expression("({[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+})$");
		if (!boost::regex_search(subkey, matches, expression)) {
			continue;
		}
		queryKey("HKEY_LOCAL_MACHINE", subkey, appResults);
		Row r;
		r["identifying_number"] = matches[0];
		for (const auto& aKey : appResults) {
			if (aKey.at("name") == "DisplayName") {
				r["name"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "DisplayVersion") {
				r["version"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "InstallSource") {
				r["install_source"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "Language") {
				r["language"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "Publisher") {
				r["publisher"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "UninstallString") {
				r["uninstall_string"] = SQL_TEXT(aKey.at("data"));
			}
			if (aKey.at("name") == "InstallDate") {
				r["install_date"] = SQL_TEXT(aKey.at("data"));
			}
		}
		results_data.push_back(r);
	}
}

QueryData genApplications(QueryContext& context) {
  QueryData results;
  queryReg(results);

  return results;
  }
}
}
