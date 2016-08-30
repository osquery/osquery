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
#include <sstream>
#include <string>

#include <stdlib.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {

std::set<long> getProcList(const QueryContext& context) {
  std::set<long> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid > 0) {
        pidlist.insert(pid);
      }
    }
    return pidlist;
  } else {
    WmiRequest request("SELECT ProcessId FROM Win32_Process");
    if (request.getStatus().ok()) {
      long placeHolder;
      Status s;
      for (auto const& result : request.results()) {
        s = result.GetLong("ProcessId", placeHolder);
        if (!s.ok()) {
          continue;
        }
        pidlist.insert(placeHolder);
      }
    }
    return pidlist;
  }
}

void genProcess(long pid, QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM Win32_Process WHERE ProcessId=" << pid;

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    if (results.size() == 1) {
      Row r;
      Status s;
      long lPlaceHolder;
      std::string sPlaceHolder;

      s = results[0].GetLong("ProcessId", lPlaceHolder);
      r["pid"] = s.ok() ? BIGINT(lPlaceHolder) : BIGINT(-1);
      s = results[0].GetString("Name", sPlaceHolder);
      r["name"] = SQL_TEXT(sPlaceHolder);
      s = results[0].GetString("ExecutablePath", sPlaceHolder);
      r["path"] = SQL_TEXT(sPlaceHolder);
      s = results[0].GetString("CommandLine", sPlaceHolder);
      r["cmdline"] = SQL_TEXT(sPlaceHolder);
      s = results[0].GetString("ExecutionState", sPlaceHolder);
      r["state"] = SQL_TEXT(sPlaceHolder);
      s = results[0].GetLong("ParentProcessId", lPlaceHolder);
      r["parent"] = BIGINT(lPlaceHolder);
      s = results[0].GetLong("Priority", lPlaceHolder);
      r["nice"] = INTEGER(lPlaceHolder);
      r["on_disk"] = osquery::pathExists(r["path"]).toString();

      // TODO: some of these such as cwd, wired_size, phys_footprint
      // should be retrievable either via Windows API or WMI
      r["cwd"] = "";
      r["root"] = "";

      r["pgroup"] = "-1";
      r["uid"] = "-1";
      r["euid"] = "-1";
      r["suid"] = "-1";
      r["gid"] = "-1";
      r["egid"] = "-1";
      r["sgid"] = "-1";

      r["wired_size"] = "0";
      r["resident_size"] = "0"; // Populate with WorkingSetSize (VT_BSTR)
      r["phys_footprint"] = "0";

      r["user_time"] = "0";
      r["system_time"] = "0";
      r["start_time"] = "0";

      results_data.push_back(r);
    }
  }
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(context);
  for (const auto& pid : pidlist) {
    genProcess(pid, results);
  }

  return results;
}
}
}
