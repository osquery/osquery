/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genListeningPorts(QueryContext& context) {
  QueryData results;

  auto sockets = SQL::selectAllFrom("process_open_sockets");

  for (const auto& socket : sockets) {
    if (socket.at("remote_port") != "0") {
      // Listening UDP/TCP ports have a remote_port == "0"
      continue;
    }

    Row r;
    r["pid"] = socket.at("pid");
    r["port"] = socket.at("local_port");
    r["protocol"] = socket.at("local_port");
    r["family"] = socket.at("family");
    r["address"] = socket.at("local_address");

    results.push_back(r);
  }

  return results;
}
}
}
