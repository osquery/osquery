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

#include <osquery/sql.h>
#include <osquery/tests/test_matchers.h>

namespace osquery {
namespace tables {

namespace {
const std::set<std::string> kExpectedColumns = {
    "interface",
    "hlim",
    "forwarding",
    "redirect",
    "rtadv",
};
}

class InterfaceIpv6Tests : public testing::Test {};

TEST_F(InterfaceIpv6Tests, test_columns_types) {
  SQL results("select * from interface_ipv6");
  EXPECT_TRUE(results.ok()) << results.getMessageString();

  for (const auto& row : results.rows()) {
    std::set<std::string> columns;
    for (const auto& column : row) {
      auto& key = column.first;
      auto& val = column.second;
      columns.insert(key);
      if (key == "interface") {
        auto intf = checkTypeAndCast<TEXT_LITERAL>(val);
        EXPECT_THAT(intf, IsNetworkIntfName());
      } else if (key == "hlim") {
        auto hlim = checkTypeAndCast<INTEGER_LITERAL>(val);
        EXPECT_THAT(hlim, IsBetween(0, 255));
      } else if (key == "forwarding") {
        auto fwd = checkTypeAndCast<INTEGER_LITERAL>(val);
        EXPECT_THAT(fwd, IsBoolean());
      } else if (key == "redirect") {
        auto redir = checkTypeAndCast<INTEGER_LITERAL>(val);
        EXPECT_THAT(redir, IsBoolean());
      } else if (key == "rtadv") {
        auto rtadv = checkTypeAndCast<INTEGER_LITERAL>(val);
        EXPECT_THAT(rtadv, IsBoolean());
      } else {
        FAIL() << "No tests found for columns \"" << key << "\"";
      }
    }
    EXPECT_EQ(kExpectedColumns, columns);
  }
}

} // namespace tables
} // namespace osquery
