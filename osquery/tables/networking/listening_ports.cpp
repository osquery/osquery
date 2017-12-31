/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genListeningPorts(QueryContext& context) {
  QueryData results;

  auto sockets = SQL::selectAllFrom("process_open_sockets");

  for (const auto& socket : sockets) {
    // 1  = AF_UNIX
    if (socket.at("family") == "1" && socket.at("path").empty()) {
      // Skip anonymous unix domain sockets
      continue;
    }

    // 2  = AF_INET
    // 10 = AF_INET6
    if ((socket.at("family") == "2" || socket.at("family") == "10") &&
        socket.at("remote_port") != "0") {
      // Listening UDP/TCP ports have a remote_port == "0"
      continue;
    }

    Row r;
    r["pid"] = socket.at("pid");

    if (socket.at("family") == "1") {
      r["path"] = socket.at("path");
    } else {
      r["address"] = socket.at("local_address");
      r["port"] = socket.at("local_port");
    }

    r["protocol"] = socket.at("protocol");
    r["family"] = socket.at("family");
    r["net_namespace"] = socket.at("net_namespace");
    r["fd"] = socket.at("fd");
    r["socket"] = socket.at("socket");

    results.push_back(r);
  }

  return results;
}
}
}
