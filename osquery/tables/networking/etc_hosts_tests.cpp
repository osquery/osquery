// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/test_util.h"
#include "osquery/database.h"

using namespace osquery::core;

namespace osquery {
namespace tables {

osquery::db::QueryData parseEtcHostsContent(const std::string& content);

class EtcHostsTests : public testing::Test {};

TEST_F(EtcHostsTests, test_parse_etc_hosts_content) {
  EXPECT_EQ(parseEtcHostsContent(getEtcHostsContent()),
            getEtcHostsExpectedResults());
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
