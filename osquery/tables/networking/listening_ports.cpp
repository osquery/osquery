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

namespace {
const std::string kAF_UNIX = "1";
const std::string kAF_INET = "2";
const std::string kAF_INET6 = "10";
} // namespace

namespace osquery {
namespace tables {
QueryData genListeningPorts(QueryContext& context) {
  QueryData results;

  auto sockets = SQL::selectAllFrom("process_open_sockets");

  for (const auto& socket : sockets) {
    if (socket.at("family") == kAF_UNIX && socket.at("path").empty()) {
      // Skip anonymous unix domain sockets
      continue;
    }

    if ((socket.at("family") == kAF_INET || socket.at("family") == kAF_INET6) &&
        socket.at("remote_port") != "0") {
      // Listening UDP/TCP ports have a remote_port == "0"
      continue;
    }

    Row r;
    r["pid"] = socket.at("pid");

    if (socket.at("family") == kAF_UNIX) {
      r["port"] = "0";
      r["path"] = socket.at("path");
      r["socket"] = "0";
    } else {
      r["address"] = socket.at("local_address");
      r["port"] = socket.at("local_port");

      auto socket_it = socket.find("socket");
      if (socket_it != socket.end()) {
        r["socket"] = socket_it->second;
      } else {
        r["socket"] = "0";
      }
    }

    r["protocol"] = socket.at("protocol");
    r["family"] = socket.at("family");

    auto fd_it = socket.find("fd");
    if (fd_it != socket.end()) {
      r["fd"] = fd_it->second;
    } else {
      r["fd"] = "0";
    }

    // When running under linux, we also have the user namespace
    // column available. It can be used with the docker_containers
    // table
    if (isPlatform(PlatformType::TYPE_LINUX)) {
      r["net_namespace"] = socket.at("net_namespace");
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
