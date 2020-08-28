/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

QueryData genPipes(QueryContext& context) {
  QueryData results;
  WIN32_FIND_DATAW findFileData;

  std::wstring pipeSearch = L"\\\\.\\pipe\\*";
  memset(&findFileData, 0, sizeof(findFileData));
  auto findHandle = FindFirstFileW(pipeSearch.c_str(), &findFileData);

  if (findHandle == INVALID_HANDLE_VALUE) {
    LOG(INFO) << "Failed to enumerate system pipes";
    return results;
  }

  do {
    Row r;

    r["name"] = wstringToString(findFileData.cFileName);

    unsigned long pid = 0;
    auto pipePath = L"\\\\.\\pipe\\" + std::wstring(findFileData.cFileName);
    auto pipeHandle = CreateFileW(
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
  } while (FindNextFileW(findHandle, &findFileData));

  FindClose(findHandle);
  return results;
}
}
}
