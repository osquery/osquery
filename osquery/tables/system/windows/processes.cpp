/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <map>
#include <string>

#include <osquery/utils/system/system.h>

#include <iomanip>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/filesystem/fileops.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
int getUidFromSid(PSID sid);
int getGidFromSid(PSID sid);
namespace tables {

const std::map<unsigned long, std::string> kMemoryConstants = {
    {PAGE_EXECUTE, "PAGE_EXECUTE"},
    {PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ"},
    {PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE"},
    {PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY"},
    {PAGE_NOACCESS, "PAGE_NOACCESS"},
    {PAGE_READONLY, "PAGE_READONLY"},
    {PAGE_READWRITE, "PAGE_READWRITE"},
    {PAGE_WRITECOPY, "PAGE_WRITECOPY"},
    {PAGE_GUARD, "PAGE_GUARD"},
    {PAGE_NOCACHE, "PAGE_NOCACHE"},
    {PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE"},
};
const std::string kWinProcPerfQuery =
    "SELECT IDProcess, ElapsedTime, HandleCount, PercentProcessorTime FROM "
    "Win32_PerfRawData_PerfProc_Process";

/// Given a pid, enumerates all loaded modules and memory pages for that process
Status genMemoryMap(unsigned long pid, QueryData& results) {
  auto proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (proc == nullptr) {
    Row r;
    r["pid"] = INTEGER(pid);
    r["start"] = INTEGER(-1);
    r["end"] = INTEGER(-1);
    r["permissions"] = "";
    r["offset"] = INTEGER(-1);
    r["device"] = "-1";
    r["inode"] = INTEGER(-1);
    r["path"] = "";
    r["pseudo"] = INTEGER(-1);
    results.push_back(r);
    return Status(1, "Failed to open handle to process " + std::to_string(pid));
  }
  auto modSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (modSnap == INVALID_HANDLE_VALUE) {
    CloseHandle(proc);
    return Status(1, "Failed to enumerate modules for " + std::to_string(pid));
  }

  auto formatMemPerms = [](unsigned long perm) {
    std::vector<std::string> perms;
    for (const auto& kv : kMemoryConstants) {
      if (kv.first & perm) {
        perms.push_back(kv.second);
      }
    }
    return osquery::join(perms, " | ");
  };

  MODULEENTRY32 me;
  MEMORY_BASIC_INFORMATION mInfo;
  me.dwSize = sizeof(MODULEENTRY32);
  auto ret = Module32First(modSnap, &me);
  while (ret != FALSE) {
    for (auto p = me.modBaseAddr;
         VirtualQueryEx(proc, p, &mInfo, sizeof(mInfo)) == sizeof(mInfo) &&
         p < (me.modBaseAddr + me.modBaseSize);
         p += mInfo.RegionSize) {
      Row r;
      r["pid"] = INTEGER(pid);
      std::stringstream ssStart;
      ssStart << std::hex << mInfo.BaseAddress;
      r["start"] = "0x" + ssStart.str();
      std::stringstream ssEnd;
      ssEnd << std::hex << std::setfill('0') << std::setw(16)
            << reinterpret_cast<unsigned long long>(mInfo.BaseAddress) +
                   mInfo.RegionSize;
      r["end"] = "0x" + ssEnd.str();
      r["permissions"] = formatMemPerms(mInfo.Protect);
      r["offset"] =
          BIGINT(reinterpret_cast<unsigned long long>(mInfo.AllocationBase));
      r["device"] = "-1";
      r["inode"] = INTEGER(-1);
      r["path"] = me.szExePath;
      r["pseudo"] = INTEGER(-1);
      results.push_back(r);
    }
    ret = Module32Next(modSnap, &me);
  }
  CloseHandle(proc);
  CloseHandle(modSnap);
  return Status(0, "Ok");
}

/// Helper function for enumerating all active processes on the system
Status getProcList(std::set<long>& pids) {
  auto procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (procSnap == INVALID_HANDLE_VALUE) {
    return Status(1, "Failed to open process snapshot");
  }

  PROCESSENTRY32 procEntry;
  procEntry.dwSize = sizeof(PROCESSENTRY32);
  auto ret = Process32First(procSnap, &procEntry);

  if (ret == FALSE) {
    CloseHandle(procSnap);
    return Status(1, "Failed to open first process");
  }

  while (ret != FALSE) {
    pids.insert(procEntry.th32ProcessID);
    ret = Process32Next(procSnap, &procEntry);
  }

  CloseHandle(procSnap);
  return Status(0, "Ok");
}

void genProcess(const long pid,
                const WmiResultItem& result,
                Row& r,
                QueryContext& context) {
  Status s;
  long lPlaceHolder;
  std::string sPlaceHolder;

  /// Store current process pid for more efficient API use.
  auto currentPid = GetCurrentProcessId();

  long uid = -1;
  long gid = -1;
  HANDLE hProcess = nullptr;

  if (context.isAnyColumnUsed({"uid",
                               "gid",
                               "cwd",
                               "root",
                               "user_time",
                               "system_time",
                               "start_time",
                               "is_elevated_token"})) {
    if (pid == currentPid) {
      hProcess = GetCurrentProcess();
    } else {
      hProcess =
          OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
    }

    if (GetLastError() == ERROR_ACCESS_DENIED) {
      uid = 0;
      gid = 0;
    }
  }

  result.GetString("Name", r["name"]);
  result.GetString("ExecutablePath", r["path"]);
  result.GetString("CommandLine", r["cmdline"]);
  result.GetString("ExecutionState", r["state"]);
  result.GetLong("ParentProcessId", lPlaceHolder);
  r["parent"] = BIGINT(lPlaceHolder);
  result.GetLong("Priority", lPlaceHolder);
  r["nice"] = INTEGER(lPlaceHolder);
  r["on_disk"] = osquery::pathExists(r["path"]).toString();
  result.GetLong("ThreadCount", lPlaceHolder);
  r["threads"] = INTEGER(lPlaceHolder);
  result.GetString("PrivatePageCount", sPlaceHolder);
  r["wired_size"] = BIGINT(sPlaceHolder);
  result.GetString("WorkingSetSize", sPlaceHolder);
  r["resident_size"] = sPlaceHolder;
  result.GetString("VirtualSize", sPlaceHolder);
  r["total_size"] = BIGINT(sPlaceHolder);

  if (context.isAnyColumnUsed({"cwd", "root"})) {
    std::vector<char> fileName(MAX_PATH + 1, 0x0);
    if (pid == currentPid) {
      GetModuleFileName(nullptr, fileName.data(), MAX_PATH);
    } else {
      GetModuleFileNameEx(hProcess, nullptr, fileName.data(), MAX_PATH);
    }

    r["cwd"] = SQL_TEXT(fileName.data());
    r["root"] = r["cwd"];
  }

  r["pgroup"] = "-1";
  r["euid"] = "-1";
  r["suid"] = "-1";
  r["egid"] = "-1";
  r["sgid"] = "-1";

  if (context.isAnyColumnUsed({"user_time", "system_time", "start_time"})) {
    FILETIME createTime;
    FILETIME exitTime;
    FILETIME kernelTime;
    FILETIME userTime;
    auto procRet = GetProcessTimes(
        hProcess, &createTime, &exitTime, &kernelTime, &userTime);
    if (procRet == FALSE) {
      r["user_time"] = BIGINT(-1);
      r["system_time"] = BIGINT(-1);
      r["start_time"] = BIGINT(-1);
    } else {
      // Windows stores proc times in 100 nanosecond ticks
      ULARGE_INTEGER utime;
      utime.HighPart = userTime.dwHighDateTime;
      utime.LowPart = userTime.dwLowDateTime;
      r["user_time"] = BIGINT(utime.QuadPart / 10000);
      utime.HighPart = kernelTime.dwHighDateTime;
      utime.LowPart = kernelTime.dwLowDateTime;
      r["system_time"] = BIGINT(utime.QuadPart / 10000);
      r["start_time"] = BIGINT(osquery::filetimeToUnixtime(createTime));
    }
  }

  if (context.isAnyColumnUsed({"uid", "gid", "is_elevated_token"})) {
    /// Get the process UID and GID from its SID
    HANDLE tok = nullptr;
    std::vector<char> tokUser(sizeof(TOKEN_USER), 0x0);
    auto ret = OpenProcessToken(hProcess, TOKEN_READ, &tok);
    if (ret != 0 && tok != nullptr) {
      unsigned long tokOwnerBuffLen;
      ret = GetTokenInformation(tok, TokenUser, nullptr, 0, &tokOwnerBuffLen);
      if (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        tokUser.resize(tokOwnerBuffLen);
        ret = GetTokenInformation(
            tok, TokenUser, tokUser.data(), tokOwnerBuffLen, &tokOwnerBuffLen);
      }

      // Check if the process is using an elevated token
      auto elevated = FALSE;
      TOKEN_ELEVATION Elevation;
      DWORD cbSize = sizeof(TOKEN_ELEVATION);
      if (GetTokenInformation(
              tok, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
        elevated = Elevation.TokenIsElevated;
      }

      r["is_elevated_token"] = elevated ? INTEGER(1) : INTEGER(0);
    }
    if (uid != 0 && ret != 0 && !tokUser.empty()) {
      auto sid = PTOKEN_OWNER(tokUser.data())->Owner;
      r["uid"] = INTEGER(getUidFromSid(sid));
      r["gid"] = INTEGER(getGidFromSid(sid));
    } else {
      r["uid"] = INTEGER(uid);
      r["gid"] = INTEGER(gid);
    }
    if (tok != nullptr) {
      CloseHandle(tok);
      tok = nullptr;
    }
  }

  if (hProcess != nullptr) {
    CloseHandle(hProcess);
  }
}

// collect perf data into a hashmap by pid to later be refferenced

void genPerfPerProcess(
    std::map<std::int32_t, std::map<std::string, std::int64_t>>& perfData) {
  const WmiRequest request(kWinProcPerfQuery);

  if (!request.getStatus().ok()) {
    VLOG(1) << "Failed to query process perf data from WMI";
    return;
  }

  const auto& results = request.results();
  for (const auto& result : results) {
    std::map<std::string, std::int64_t> processData;
    long processID;
    long handleCount = 0;
    std::string elapsedTime;
    std::string percentProcessorTime;

    result.GetString("ElapsedTime", elapsedTime);
    result.GetLong("HandleCount", handleCount);
    result.GetString("PercentProcessorTime", percentProcessorTime);
    processData["elapsed_time"] = std::stoll(elapsedTime);
    processData["handle_count"] = handleCount;
    processData["percent_processor_time"] = std::stoll(percentProcessorTime);
    result.GetLong("IDProcess", processID);
    perfData[processID] = processData;
  }
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  std::string query = "SELECT * FROM Win32_Process";

  std::set<long> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid > 0) {
        pidlist.insert(pid);
      }
    }
    // None of the constraints returned valid pids, bail out early
    if (pidlist.empty()) {
      return results;
    }
  }

  if (pidlist.size() > 0) {
    std::vector<std::string> constraints;
    for (const auto& pid : pidlist) {
      constraints.push_back("ProcessId=" + std::to_string(pid));
    }
    if (constraints.size() > 0) {
      query += " WHERE " + boost::algorithm::join(constraints, " OR ");
    }
  }

  // get per process data
  std::map<std::int32_t, std::map<std::string, std::int64_t>> perfData;
  if (context.isAnyColumnUsed(
          {"elapsed_time", "handle_count", "percent_processor_time"})) {
    genPerfPerProcess(perfData);
  }

  const WmiRequest request(query);
  if (request.getStatus().ok()) {
    for (const auto& item : request.results()) {
      long pid = 0;
      Row r;
      if (item.GetLong("ProcessId", pid).ok()) {
        r["pid"] = BIGINT(pid);
        // add per process perf data
        if (context.isAnyColumnUsed(
                {"elapsed_time", "handle_count", "percent_processor_time"})) {
          std::map<std::string, std::int64_t> procPerfData;
          procPerfData = perfData[pid];
          r["elapsed_time"] = BIGINT(procPerfData["elapsed_time"]);
          r["handle_count"] = BIGINT(procPerfData["handle_count"]);
          r["percent_processor_time"] =
              BIGINT(procPerfData["percent_processor_time"]);
        }

        genProcess(pid, item, r, context);
      } else {
        r["pid"] = BIGINT(-1);
      }
      results.push_back(r);
    }
  }

  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;

  std::set<long> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid > 0) {
        pidlist.insert(pid);
      }
    }
  }
  if (pidlist.empty()) {
    getProcList(pidlist);
  }

  for (const auto& pid : pidlist) {
    auto s = genMemoryMap(pid, results);
    if (!s.ok()) {
      VLOG(1) << s.getMessage();
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
