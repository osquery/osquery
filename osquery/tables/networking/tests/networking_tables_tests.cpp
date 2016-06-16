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

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

osquery::QueryData parseEtcHostsContent(const std::string& content);
osquery::QueryData parseEtcProtocolsContent(const std::string& content);

class NetworkingTablesTests : public testing::Test {};

TEST_F(NetworkingTablesTests, test_parse_etc_hosts_content) {
  EXPECT_EQ(parseEtcHostsContent(getEtcHostsContent()),
            getEtcHostsExpectedResults());
}

TEST_F(NetworkingTablesTests, test_parse_etc_protocols_content) {
  EXPECT_EQ(parseEtcProtocolsContent(getEtcProtocolsContent()),
            getEtcProtocolsExpectedResults());
}
}
}
