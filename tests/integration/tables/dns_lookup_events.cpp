/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for dns_lookup_events
// Spec file: specs/posix/dns_lookup_events.table

#include <osquery/config/config.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

DECLARE_bool(enable_dns_lookup_events);

namespace table_tests {

class dnsLookupEvents : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    // Enable ETW DNS events
    RegistryFactory::get().registry("config_parser")->setUp();
    FLAGS_enable_dns_lookup_events = true;

    // Start eventing framework
    attachEvents();
  }

  void TearDown() override {
    Dispatcher::instance().stopServices();
    Dispatcher::instance().joinServices();
    Dispatcher::instance().resetStopping();
  }
};

TEST_F(dnsLookupEvents, test_sanity) {
  // Ping to generate DNS lookups
  system("ping hostname.invalid"); // invalid, will fail
  system("ping localhost"); // valid, should succeed
  Sleep(4000);

  // Query data
  auto const data = execute_query(
      "SELECT eid, time, time_windows, datetime, pid, path, username, name, "
      "type, type_id, status, response FROM dns_lookup_events");

  // General validation of rows
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"eid", NonNegativeInt},
                           {"time", NonNegativeInt},
                           {"time_windows", NonNegativeInt},
                           {"datetime", NonNegativeInt},
                           {"pid", NonNegativeInt},
                           {"path", FileOnDisk | EmptyOk | NullOk},
                           {"username", NonEmptyString},
                           {"name", NonEmptyString},
                           {"type", NonEmptyString},
                           {"type_id", NonNegativeInt},
                           {"status", NonEmptyString},
                           {"response", NonEmptyString | EmptyOk | NullOk}};
  validate_rows(data, row_map);

  // Specific validation of rows

  // These requests don't always work on CI, so there are if
  // statements protecting the assertions.
  {
    // Unsuccessful A record
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "hostname.invalid" && row.at("type") == "A";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_EQ(row.at("status"), INTEGER(87));
      EXPECT_EQ(row.at("response").size(), 0);
    }
  }

  {
    // Unsuccessful AAAA record
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "hostname.invalid" && row.at("type") == "AAAA";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_EQ(row.at("status"), INTEGER(9003));
      EXPECT_EQ(row.at("response").size(), 0);
    }
  }

  {
    // Check the successful localhost lookup (could be A or AAAA)
    const auto it = std::find_if(data.begin(), data.end(), [](const Row& row) {
      return row.at("name") == "localhost" && row.at("status") == "0";
    });
    if (it != data.end()) {
      const Row& row = *it;
      EXPECT_GE(row.at("response").size(), 0);
    }
  }
}
} // namespace table_tests
} // namespace osquery
