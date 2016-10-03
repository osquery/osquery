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

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>
#include <stdlib.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/utils.h"
#include "osquery/core/windows/wmi.h"

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
  // We store the current processes PID, as there are API calls which are more
  // efficient for populating process info for the current process.
  auto currentPid = GetCurrentProcessId();

  std::stringstream ss;
  ss << "SELECT * FROM Win32_Process WHERE ProcessId=" << pid;

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    if (results.size() == 1) {
      Row r;
      Status s;
      long pid;
      long lPlaceHolder;
      std::string sPlaceHolder;
      HANDLE hProcess;

      s = results[0].GetLong("ProcessId", pid);
      r["pid"] = s.ok() ? BIGINT(pid) : BIGINT(-1);
      if (pid == currentPid) {
        hProcess = GetCurrentProcess();
      } else {
        hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
      }

      results[0].GetString("Name", r["name"]);
      results[0].GetString("ExecutablePath", r["path"]);
      results[0].GetString("CommandLine", r["cmdline"]);
      results[0].GetString("ExecutionState", r["state"]);
      results[0].GetLong("ParentProcessId", lPlaceHolder);
      r["parent"] = BIGINT(lPlaceHolder);
      results[0].GetLong("Priority", lPlaceHolder);
      r["nice"] = INTEGER(lPlaceHolder);
      r["on_disk"] = osquery::pathExists(r["path"]).toString();

      std::vector<char> fileName(MAX_PATH);
      fileName.assign(MAX_PATH + 1, '\0');
      if (pid == currentPid) {
        GetModuleFileName(nullptr, fileName.data(), MAX_PATH);
      } else {
        GetModuleFileNameEx(hProcess, nullptr, fileName.data(), MAX_PATH);
      }
      r["cwd"] = SQL_TEXT(fileName.data());
      r["root"] = r["cwd"];

      r["pgroup"] = "-1";
      r["uid"] = "-1";
      r["euid"] = "-1";
      r["suid"] = "-1";
      r["gid"] = "-1";
      r["egid"] = "-1";
      r["sgid"] = "-1";
      r["start_time"] = "0";

      // We pre-populate the info, in the event the API calls fail.
      results[0].GetString("UserModeTime", sPlaceHolder);
      long long llHolder;
      osquery::safeStrtoll(sPlaceHolder, 10, llHolder);
      r["user_time"] = BIGINT(llHolder / 10000000);
      results[0].GetString("KernelModeTime", sPlaceHolder);
      osquery::safeStrtoll(sPlaceHolder, 10, llHolder);
      r["system_time"] = BIGINT(llHolder / 10000000);

      results[0].GetString("PrivatePageCount", sPlaceHolder);
      r["wired_size"] = BIGINT(sPlaceHolder);
      results[0].GetString("WorkingSetSize", sPlaceHolder);
      r["resident_size"] = sPlaceHolder;
      results[0].GetString("VirtualSize", sPlaceHolder);
      r["total_size"] = BIGINT(sPlaceHolder);
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
