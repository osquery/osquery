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
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

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

    results.push_back(r);
    CloseHandle(pipeHandle);
  } while (FindNextFile(findHandle, &findFileData));

  FindClose(findHandle);
  return results;
}
}
}
