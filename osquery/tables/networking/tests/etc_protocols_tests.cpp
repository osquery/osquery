/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/database.h>

#include "osquery/core/test_util.h"

namespace osquery {
namespace tables {

osquery::QueryData parseEtcProtocolsContent(const std::string& content);

class EtcProtocolsTests : public testing::Test {};

TEST_F(EtcProtocolsTests, test_parse_etc_protocols_content) {
  EXPECT_EQ(parseEtcProtocolsContent(getEtcProtocolsContent()),
            getEtcProtocolsExpectedResults());
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
