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
    r["creation_time"] =
        BIGINT(filetimeToUnixtime(findFileData.ftCreationTime));
    r["last_access_time"] =
        BIGINT(filetimeToUnixtime(findFileData.ftLastAccessTime));

    unsigned long pid = 0;
    auto pipeHandle = CreateFile(
        r["path"].c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    auto ret = GetNamedPipeServerProcessId(pipeHandle, &pid);
    if (ret != TRUE) {
      ret = GetNamedPipeClientProcessId(pipeHandle, &pid);
    }
    r["pid"] = ret == TRUE ? INTEGER(pid) : "-1";

    unsigned long numInstances = 0;
    unsigned long maxCollectionCount = 0;
    unsigned long dataTimeout = 0;
    std::vector<char> userName(256, 0x0);
    ret = GetNamedPipeHandleState(pipeHandle,
                                  nullptr,
                                  &numInstances,
                                  nullptr,
                                  nullptr,
                                  userName.data(),
                                  static_cast<unsigned long>(userName.size()));

    r["instances"] = INTEGER(numInstances);
    r["user"] = std::string(userName.data());

    results.push_back(r);
  } while (FindNextFile(findHandle, &findFileData));

  FindClose(findHandle);
  return results;
}
}
}
