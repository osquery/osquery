/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

// map to get access mode string
static const std::unordered_map<ACCESS_MODE, std::string> kAccessModeToStr = {
    {NOT_USED_ACCESS, "Not Used"},
    {GRANT_ACCESS, "Grant"},
    {SET_ACCESS, "Set"},
    {DENY_ACCESS, "Deny"},
    {REVOKE_ACCESS, "Revoke"},
    {SET_AUDIT_SUCCESS, "Set Audit Success"},
    {SET_AUDIT_FAILURE, "Set Audit Failure"}};

// map to build access string
static const std::map<unsigned long, std::string> kPermVals = {
    {DELETE, "Delete"},
    {READ_CONTROL, "Read Control"},
    {WRITE_DAC, "Write DAC"},
    {WRITE_OWNER, "Write Owner"},
    {SYNCHRONIZE, "Synchronize"},
    {STANDARD_RIGHTS_REQUIRED, "Std Rights Required"},
    {STANDARD_RIGHTS_ALL, "Std Rights All"},
    {SPECIFIC_RIGHTS_ALL, "Specific Rights All"},
    {ACCESS_SYSTEM_SECURITY, "Access System Security"},
    {MAXIMUM_ALLOWED, "Maximum Allowed"},
    {GENERIC_READ, "Generic Read"},
    {GENERIC_WRITE, "Generic Write"},
    {GENERIC_EXECUTE, "Generic Execute"},
    {GENERIC_ALL, "Generic All"}};

// helper function to build access string from permission bit mask
std::string accessPermsToStr(const unsigned long pmask) {
  std::vector<std::string> permList;

  for (auto const& perm : kPermVals) {
    if ((pmask & perm.first) != 0) {
      permList.push_back(perm.second);
    }
  }

  return alg::join(permList, ",");
}

QueryData genPipes(QueryContext& context) {
  QueryData results;
  WIN32_FIND_DATA findFileData;

  std::string pipeSearch = "\\\\.\\pipe\\*";
  memset(&findFileData, 0, sizeof(findFileData));
  auto findHandle = FindFirstFileA(pipeSearch.c_str(), &findFileData);

  if (findHandle == INVALID_HANDLE_VALUE) {
    LOG(INFO) << "Failed to enumerate system pipes";
    return results;
  }

  do {
    Row r;

    r["name"] = findFileData.cFileName;

    unsigned long pid = 0;
    auto pipePath = "\\\\.\\pipe\\" + r["name"];
    auto pipeHandle = CreateFile(
        pipePath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipeHandle == INVALID_HANDLE_VALUE) {
      results.push_back(r);
      LOG(INFO) << "Failed to open handle to pipe with " << GetLastError();
      continue;
    }
    auto ret = GetNamedPipeServerProcessId(pipeHandle, &pid);
    if (ret != TRUE) {
      ret = GetNamedPipeClientProcessId(pipeHandle, &pid);
    }
    r["pid"] = (ret == TRUE) ? INTEGER(pid) : "-1";

    unsigned long numInstances = 0;
    ret = GetNamedPipeHandleState(
        pipeHandle, nullptr, &numInstances, nullptr, nullptr, nullptr, 0);
    r["instances"] = (ret != 0) ? INTEGER(numInstances) : "-1";

    unsigned long pipeFlags = 0;
    unsigned long maxInstances = 0;
    ret = GetNamedPipeInfo(
        pipeHandle, &pipeFlags, nullptr, nullptr, &maxInstances);
    r["max_instances"] = (ret == TRUE) ? INTEGER(maxInstances) : "-1";

    std::string end = ((pipeFlags & PIPE_SERVER_END) == PIPE_SERVER_END)
                          ? "PIPE_SERVER_END"
                          : "PIPE_CLIENT_END";
    std::string type = ((pipeFlags & PIPE_TYPE_MESSAGE) == PIPE_TYPE_MESSAGE)
                           ? "PIPE_TYPE_MESSAGE"
                           : "PIPE_TYPE_BYTE";
    r["flags"] = end + ',' + type;

    // Get a pointer to the existing DACL.
    PACL dacl = nullptr;
    auto result = GetNamedSecurityInfo(pipeHandle,
                                       SE_FILE_OBJECT,
                                       DACL_SECURITY_INFORMATION,
                                       nullptr,
                                       nullptr,
                                       &dacl,
                                       nullptr,
                                       nullptr);
    if (ERROR_SUCCESS != result) {
      VLOG(1) << "GetExplicitEnteriesFromAcl Error " << result;
      continue;
    }

    // get list of ACEs from DACL pointer
    unsigned long aceCount = 0;
    PEXPLICIT_ACCESS aceList = nullptr;
    result = GetExplicitEntriesFromAcl(dacl, &aceCount, &aceList);
    if (ERROR_SUCCESS != result) {
      VLOG(1) << "GetExplicitEnteriesFromAcl Error " << result;
      continue;
    }

    // Loop through list of entries
    auto aceItem = aceList;
    for (unsigned long aceIndex = 0; aceIndex < aceCount;
         aceItem++, aceIndex++) {

      auto perms = accessPermsToStr(aceItem->grfAccessPermissions);
      auto accessMode = kAccessModeToStr.find(aceItem->grfAccessMode)->second;

      r["type"] = TEXT(accessMode);
      r["access"] = TEXT(perms);
      results.push_back(std::move(r));
    }

    results.push_back(r);
    CloseHandle(pipeHandle);
  } while (FindNextFile(findHandle, &findFileData));

  FindClose(findHandle);
  return results;
}
}
}

