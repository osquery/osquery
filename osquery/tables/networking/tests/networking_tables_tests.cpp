/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

QueryData parseEtcHostsContent(const std::string& content);
QueryData parseEtcProtocolsContent(const std::string& content);

class NetworkingTablesTests : public testing::Test {};

TEST_F(NetworkingTablesTests, test_parse_etc_hosts_content) {
  EXPECT_EQ(parseEtcHostsContent(getEtcHostsContent()),
            getEtcHostsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_parse_etc_protocols_content) {
  EXPECT_EQ(parseEtcProtocolsContent(getEtcProtocolsContent()),
            getEtcProtocolsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_listening_ports) {
  auto& server = TLSServerRunner::instance();
  server.start();
  auto results = SQL::selectAllFrom("listening_ports");

  // Expect to find a process PID for the server.
  std::string pid;
  for (const auto& row : results) {
    // We are not interested in rows without ports (i.e. UNIX sockets)
    const auto& listening_port = row.at("port");
    if (listening_port.empty()) {
      continue;
    }

    if (listening_port == server.port()) {
      const auto& process_id = row.at("pid");
      if (process_id.empty()) {
        VLOG(1) << "Failed to acquire the process id";
        break;
      }

      pid = process_id;
      break;
    }
  }

  EXPECT_GT(pid.size(), 0U);
  EXPECT_NE(pid, "-1");
  server.stop();
}

TEST_F(NetworkingTablesTests, test_address_details_join) {
  // Expect that we can join interface addresses with details
  auto query =
      "select * from interface_details id, interface_addresses ia "
      "on ia.interface = id.interface "
      "where ia.address = '127.0.0.1';";

  auto results = SQL(query);
  EXPECT_GT(results.rows().size(), 0U);
}
} // namespace tables
} // namespace osquery
