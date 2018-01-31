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

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_listening_ports_defs.hpp>

namespace osquery {
namespace tables {

typedef std::pair<std::string, std::string> ProtoFamilyPair;
typedef std::map<std::string, std::vector<ProtoFamilyPair>> PortMap;

QueryData genListeningPorts(QueryContext& context) {
  QueryData results;

  auto sockets = SQL::selectAllFrom("process_open_sockets");

  PortMap ports;
  for (const auto& socket : sockets) {
    if (socket.at("remote_port") != "0") {
      // Listening UDP/TCP ports have a remote_port == "0"
      continue;
    }

    if (ports.count(socket.at("local_port")) > 0) {
      bool duplicate = false;
      for (const auto& entry : ports[socket.at("local_port")]) {
        if (entry.first == socket.at("protocol") &&
            entry.second == socket.at("family")) {
          duplicate = true;
          break;
        }
      }

      if (duplicate) {
        // There is a duplicate socket descriptor for this bind.
        continue;
      }
    }

    // Add this family/protocol/port bind to the tracked map.
    ports[socket.at("local_port")].push_back(
        std::make_pair(socket.at("protocol"), socket.at("family")));

    Row r;
    r["pid"] = socket.at("pid");
    r["port"] = socket.at("local_port");
    r["protocol"] = socket.at("protocol");
    r["family"] = socket.at("family");
    r["address"] = socket.at("local_address");

    results.push_back(r);
  }

  return results;
}
}
}
