/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <lmcons.h>

#include <boost/filesystem/operations.hpp>

#include <osquery/core.h>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

std::string getUserId() {
  std::vector<unsigned char> user_name(UNLEN + 1);
  user_name.assign(UNLEN + 1, '\0');
  DWORD size = user_name.size() - 1;

  if (!::GetUserNameA((LPSTR) &user_name[0], &size)) {
    return "";
  }

  return std::string((const char *)&user_name[0], size - 1);
}

std::unique_ptr<PlatformProcess> launchTestServer(const std::string &port) {
  std::unique_ptr<PlatformProcess> server;

  STARTUPINFOA si = { 0 };
  PROCESS_INFORMATION pi = { 0 };

  auto argv = "python " + kTestDataPath + "/test_http_server.py --tls " + port;
  std::vector<char> mutable_argv(argv.begin(), argv.end());
  si.cb = sizeof(si);

  auto drive = getEnvVar("SystemDrive");
  std::string python_path("");
  if (drive.is_initialized()) {
    python_path = *drive;
  }

  // Python is installed here if provisioning script is used
  python_path += "\\tools\python2\\python.exe";
  if (::CreateProcessA(python_path.c_str(), &mutable_argv[0], NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)) {
    server.reset(new PlatformProcess(pi.hProcess));
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
  }

  return std::move(server);
}
}
