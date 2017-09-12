/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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

  std::string pid;
  for (const auto& row : results) {
    // Expect to find a process PID for the server.
    if (row.at("port") == server.port()) {
      pid = row.at("pid");
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

  auto results = SQL::SQL(query);
  EXPECT_GT(results.rows().size(), 0U);
}
}
}
