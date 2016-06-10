/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <boost/filesystem/operations.hpp>

#include <osquery/core.h>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

std::string getUserId() {
  return std::to_string(getuid());
}

std::unique_ptr<PlatformProcess> launchTestServer(const std::string &port) {
  std::unique_ptr<PlatformProcess> server;

  int server_pid = fork();
  if (server_pid == 0) {
    // Start a python TLS/HTTPS or HTTP server.
    auto script = kTestDataPath + "/test_http_server.py --tls " + port;
    execlp("sh", "sh", "-c", script.c_str(), nullptr);
    ::exit(0);
  } else if (server_pid > 0) {
    server.reset(new PlatformProcess(server_pid));
  }

  return server;
}
}
