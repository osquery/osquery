/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {
namespace tables {

QueryData genPipes(QueryContext& context) {
  QueryData results;
  WIN32_FIND_DATA findFileData;

  std::string pipePrefix = "\\\\.\\pipe\\*";
  memset(&findFileData, 0, sizeof(findFileData));
  auto findHandle = FindFirstFileA(pipePrefix.c_str(), &findFileData);

  if (findHandle == INVALID_HANDLE_VALUE) {
    LOG(INFO) << "Failed to enumerate system pipes";
    return results;
  }

  do {
    Row r;

    r["name"] = findFileData.cFileName;
    r["path"] = "\\\\.\\pipe\\" + r["name"];

    unsigned long pid = 0;
    auto pipeHandle = CreateFile(
        r["path"].c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    auto ret = GetNamedPipeServerProcessId(pipeHandle, &pid);
    if (ret != TRUE) {
      ret = GetNamedPipeClientProcessId(pipeHandle, &pid);
    }
    r["pid"] = ret == TRUE ? INTEGER(pid) : "-1";

    unsigned long numInstances = 0;
    GetNamedPipeHandleState(
        pipeHandle, nullptr, &numInstances, nullptr, nullptr, nullptr, 0);
    r["instances"] = INTEGER(numInstances);

    unsigned long pipeFlags = 0;
    unsigned long maxInstances = 0;
    ret = GetNamedPipeInfo(
        pipeHandle, &pipeFlags, nullptr, nullptr, &maxInstances);
    r["max_instances"] = ret == TRUE ? INTEGER(maxInstances) : "-1";

    std::string end = (pipeFlags & PIPE_SERVER_END) == PIPE_SERVER_END
                          ? "PIPE_SERVER_END"
                          : "PIPE_CLIENT_END";
    std::string type = (pipeFlags & PIPE_TYPE_MESSAGE) == PIPE_TYPE_MESSAGE
                           ? "PIPE_TYPE_MESSAGE"
                           : "PIPE_TYPE_BYTE";
    r["flags"] = end + " | " + type;

    results.push_back(r);
    CloseHandle(pipeHandle);
  } while (FindNextFile(findHandle, &findFileData));

  FindClose(findHandle);
  return results;
}
}
}
