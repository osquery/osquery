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

#define _WIN32_DCOM

#include <Windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include <osquery/filesystem/fileops.h>

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

/// Given a pid, enumerates all loaded modules and memory pages for that process
Status genMemoryMap(unsigned long pid, QueryData& results) {
  auto proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (proc == INVALID_HANDLE_VALUE) {
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

void genProcess(const WmiResultItem& result, QueryData& results_data) {
  Row r;
  Status s;
  long pid;
  long lPlaceHolder;
  std::string sPlaceHolder;

  /// Store current process pid for more efficient API use.
  auto currentPid = GetCurrentProcessId();

  s = result.GetLong("ProcessId", pid);
  r["pid"] = s.ok() ? BIGINT(pid) : BIGINT(-1);

  long uid = -1;
  long gid = -1;
  HANDLE hProcess = nullptr;
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
  r["euid"] = "-1";
  r["suid"] = "-1";
  r["egid"] = "-1";
  r["sgid"] = "-1";

  FILETIME createTime;
  FILETIME exitTime;
  FILETIME kernelTime;
  FILETIME userTime;
  auto procRet =
      GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime);
  if (procRet == FALSE) {
    r["user_time"] = BIGINT(-1);
    r["system_time"] = BIGINT(-1);
    r["start_time"] = BIGINT(-1);
  } else {
    // Windows stores proc times in 100 nanosecond ticks
    ULARGE_INTEGER utime;
    utime.HighPart = userTime.dwHighDateTime;
    utime.LowPart = userTime.dwLowDateTime;
    r["user_time"] = BIGINT(utime.QuadPart / 10000000);
    utime.HighPart = kernelTime.dwHighDateTime;
    utime.LowPart = kernelTime.dwLowDateTime;
    r["system_time"] = BIGINT(utime.QuadPart / 10000000);
    r["start_time"] = BIGINT(osquery::filetimeToUnixtime(createTime));
  }

  result.GetString("PrivatePageCount", sPlaceHolder);
  r["wired_size"] = BIGINT(sPlaceHolder);
  result.GetString("WorkingSetSize", sPlaceHolder);
  r["resident_size"] = sPlaceHolder;
  result.GetString("VirtualSize", sPlaceHolder);
  r["total_size"] = BIGINT(sPlaceHolder);

  /// Get the process UID and GID from its SID
  HANDLE tok = nullptr;
  std::vector<char> tokOwner(sizeof(TOKEN_OWNER), 0x0);
  auto ret = OpenProcessToken(hProcess, TOKEN_READ, &tok);
  if (ret != 0 && tok != nullptr) {
    unsigned long tokOwnerBuffLen;
    ret = GetTokenInformation(tok, TokenOwner, nullptr, 0, &tokOwnerBuffLen);
    if (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      tokOwner.resize(tokOwnerBuffLen);
      ret = GetTokenInformation(
          tok, TokenOwner, tokOwner.data(), tokOwnerBuffLen, &tokOwnerBuffLen);
    }
  }
  if (uid != 0 && ret != 0 && !tokOwner.empty()) {
    auto sid = PTOKEN_OWNER(tokOwner.data())->Owner;
    r["uid"] = INTEGER(getUidFromSid(sid));
    r["gid"] = INTEGER(getGidFromSid(sid));
  } else {
    r["uid"] = INTEGER(uid);
    r["gid"] = INTEGER(gid);
  }

  if (hProcess != nullptr) {
    CloseHandle(hProcess);
  }
  if (tok != nullptr) {
    CloseHandle(tok);
    tok = nullptr;
  }
  results_data.push_back(r);
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

  WmiRequest request(query);
  if (request.getStatus().ok()) {
    for (const auto& item : request.results()) {
      long pid = 0;
      if (item.GetLong("ProcessId", pid).ok()) {
        genProcess(item, results);
      }
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
