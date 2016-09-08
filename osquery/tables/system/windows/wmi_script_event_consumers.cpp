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

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {


QueryData genScriptConsumers(QueryContext& context) {
  QueryData results_data;
  std::stringstream ss;
  ss << "SELECT * FROM ActiveScriptEventConsumer";

  WmiRequest request(ss.str(), L"ROOT\\Subscription");
  if (request.getStatus().ok()) {
	std::vector<WmiResultItem>& results = request.results();
	for (const auto& result : results) {
		Row r;
		Status s;
		std::string sPlaceHolder;

		s = result.GetString("ScriptText", sPlaceHolder);
		r["script_text"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("ScriptFileName", sPlaceHolder);
		r["script_file_name"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("ScriptingEngine", sPlaceHolder);
		r["scripting_engine"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Name", sPlaceHolder);
		r["name"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("__CLASS", sPlaceHolder);
		r["__class"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("__RELPATH", sPlaceHolder);
		r["__relpath"] = SQL_TEXT(sPlaceHolder);
		results_data.push_back(r);
	}
  }
  
  return results_data;
}
}
}