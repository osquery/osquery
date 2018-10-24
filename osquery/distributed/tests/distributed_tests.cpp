/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

#include "mock_distributed_plugin.h"
#include "osquery/core/json.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);

namespace osquery {

DECLARE_bool(distributed_write_individually);
DECLARE_uint64(distributed_intra_sleep);

class DistributedTests : public testing::Test {
 protected:
  void TearDown() override {
    stopServer();
  }

  void startServer() {
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();
    clearNodeKey();

    distributed_tls_read_endpoint_ =
        Flag::getValue("distributed_tls_read_endpoint");
    Flag::updateValue("distributed_tls_read_endpoint", "/distributed_read");

    distributed_tls_write_endpoint_ =
        Flag::getValue("distributed_tls_write_endpoint");
    Flag::updateValue("distributed_tls_write_endpoint", "/distributed_write");

    Registry::get().setActive("distributed", "tls");
    server_started_ = true;
  }
  void stopServer() {
    if (server_started_) {
      TLSServerRunner::stop();
      TLSServerRunner::unsetClientConfig();
      clearNodeKey();

      Flag::updateValue("distributed_tls_read_endpoint",
                        distributed_tls_read_endpoint_);
      Flag::updateValue("distributed_tls_write_endpoint",
                        distributed_tls_write_endpoint_);
    }
  }

 protected:
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;

 private:
  bool server_started_{false};
};

TEST_F(DistributedTests, test_workflow) {
  startServer();

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(0U, dist.numDistWrites());

  EXPECT_EQ(dist.getPendingQueryCount(), 2U);
  EXPECT_EQ(dist.results_.size(), 2U);
  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 0U);
  EXPECT_EQ(dist.results_.size(), 0U);

  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());
}

/*
 * At startup, Distributed should check 'distributed_work' key and
 * report status interrupted (9) for all queries.  Here we make
 * sure the 'distributed_work' value is removed after pullUpdates().
 */
TEST_F(DistributedTests, test_report_interrupted) {
  static std::string strLastWork =
      "{\"queries\":{\"99_1\":\"SELECT timestamp FROM time\",\"99_2\":\"SELECT "
      "year FROM time\"}}";

  startServer();

  setDatabaseValue(kPersistentSettings, "distributed_work", strLastWork);

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());

  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());

  std::string strval;
  getDatabaseValue(kPersistentSettings, "distributed_work", strval);

  // should be replaced by server configured queries pullUpdates() received.
  EXPECT_FALSE(strLastWork == strval);

  // finish up so there isn't DB state left for other tests
  dist.runQueries();
}

static bool EnableMockDistPlugin() {
  auto& rf = RegistryFactory::get();
  auto status = rf.setActive("distributed", "mock");
  EXPECT_TRUE(status.ok());
  return status.ok();
}

/*
 * If a distributed query contains discovery queries:
 *  - If all queries return more than zero rows, run 'queries'.  Otherwise,
 * return empty results.
 */
TEST_F(DistributedTests, test_discovery) {
  static const std::string strAlwaysDiscoveryQueriesJson =
      "{\"discovery\":{\"dos\":\"SELECT * FROM time WHERE year > "
      "1900\"},\"queries\":{\"1A\":\"SELECT year FROM time\",\"1B\":\"SELECT "
      "timestamp FROM time\"}}";
  static const std::string strNeverDiscoveryQueriesJson =
      "{\"discovery\":{\"uno\":\"SELECT * FROM time WHERE "
      "year=1902\",\"dos\":\"SELECT * FROM time WHERE year > "
      "1900\"},\"queries\":{\"1A\":\"SELECT year FROM time\",\"1B\":\"SELECT "
      "timestamp FROM time\"}}";

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  auto status = MockDistributedSetReadValue(strNeverDiscoveryQueriesJson);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();
  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(status.toString(), "OK");
  EXPECT_EQ(1U, dist.numDistWrites());
  EXPECT_EQ(1U, dist.numDistReads());

  auto writes = std::vector<std::string>();

  status = MockDistributedGetWrites(writes);
  EXPECT_TRUE(status.ok());

  // discovery should fail, so result should have zero rows

  auto response_json1 = writes[0];

  // This discovery should always pass, should have 1 row

  status = MockDistributedSetReadValue(strAlwaysDiscoveryQueriesJson);

  dist.pullUpdates();
  dist.runQueries();

  writes.clear();
  status = MockDistributedGetWrites(writes);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(2, writes.size());

  auto response_json2 = writes[1];

  EXPECT_NE(response_json1, response_json2);
}

TEST_F(DistributedTests, test_write_endpoint_down) {
  static std::string strQuery =
      "{\"queries\":{\"C1\":\"SELECT year FROM time\",\"C2\":\"SELECT "
      "timestamp FROM time\"}}";

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  auto status = MockDistributedSetReadValue(strQuery);
  EXPECT_TRUE(status.ok());

  MockDistributedWriteEndpointEnabled(false);

  auto dist = Distributed();
  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_FALSE(status.ok());

  // NOTE : results get dropped

  // Try again with empty read, and write endpoint back up

  status = MockDistributedSetReadValue("{}");
  MockDistributedWriteEndpointEnabled(false);

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries(); // no results to send, will not call write
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(2U, dist.numDistReads());
  EXPECT_EQ(1U, dist.numDistWrites());

  MockDistributedWriteEndpointEnabled(true);
}

/*
 * Distributed work with many queries might want to be reported
 * individually, rather than waiting on all to complete.  Especially
 * if some queries have big result sets that would be kept in memory.
 * This test will set FLAGS_distributed_write_individually = true
 * and make sure each query is reported individually.
 */
TEST_F(DistributedTests, can_report_individually) {
  static std::string strQuery =
      "{\"queries\":{\"D1\":\"SELECT year FROM time\", \"D2\":\"SELECT day "
      "FROM time\", \"D3\":\"SELECT timestamp FROM time\"}}";

  startServer();

  FLAGS_distributed_write_individually = true;

  if (!EnableMockDistPlugin()) {
    return;
  }

  MockDistributedClearWrites();

  auto status = MockDistributedSetReadValue(strQuery);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(1U, dist.numDistReads());
  EXPECT_EQ(3U, dist.numDistWrites());

  auto writes = std::vector<std::string>();

  status = MockDistributedGetWrites(writes);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(3, writes.size());

  // try again with flag off

  FLAGS_distributed_write_individually = false;
  MockDistributedClearWrites();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(2U, dist.numDistReads());
  EXPECT_EQ(4U, dist.numDistWrites());

  status = MockDistributedGetWrites(writes);
  EXPECT_EQ(4, writes.size());
}

/*
 * In this case, the first queries object is the one that gets used.
 * the D3 query is never executed or reported.
 */
TEST_F(DistributedTests, queries_appears_twice) {
  static const std::string strQuery =
      "{\"queries\":{\"D1\":\"SELECT year FROM time\", \"D2\":\"SELECT day "
      "FROM time\"},\"queries\":{\"D3\":\"SELECT timestamp FROM time\"}}";

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  FLAGS_distributed_write_individually = true;
  MockDistributedClearWrites();
  auto status = MockDistributedSetReadValue(strQuery);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(1U, dist.numDistReads());
  EXPECT_EQ(2U, dist.numDistWrites());

  auto writes = std::vector<std::string>();
  status = MockDistributedGetWrites(writes);
  EXPECT_EQ(2, writes.size());

  FLAGS_distributed_write_individually = false;
}

TEST_F(DistributedTests, empty) {
  static const std::string strQueryNoQueries = "{\"queries\":{}}";

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  auto status = MockDistributedSetReadValue(strQueryNoQueries);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(1U, dist.numDistReads());
  EXPECT_EQ(0U, dist.numDistWrites());
}

TEST_F(DistributedTests, accelerate_for_minute) {
  static const std::string strQueryAccel = "{\"accelerate\":60}";

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  std::string strExp1 = "";
  getDatabaseValue(
      kPersistentSettings, "distributed_accelerate_checkins_expire", strExp1);

  auto status = MockDistributedSetReadValue(strQueryAccel);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(1U, dist.numDistReads());
  EXPECT_EQ(0U, dist.numDistWrites());

  std::string strExp2 = "";
  getDatabaseValue(
      kPersistentSettings, "distributed_accelerate_checkins_expire", strExp2);
  EXPECT_NE(strExp1, strExp2);

  deleteDatabaseValue(kPersistentSettings,
                      "distributed_accelerate_checkins_expire");
}

TEST_F(DistributedTests, bad_docs) {
  static const std::string strQueryEmpty = "";
  static const std::string strQueryNotObject =
      "{\"queries\":[\"SELECT * FROM time\"]}";
  static const std::string strQueryIntId =
      "{\"queries\":{2:\"SELECT * FROM time\"}}";
  static const std::string strQueryNegativeAccel = "{\"accelerate\": -300 }";
  static const std::string strQueryAccelLong = "{\"accelerate\": 5000 }";

  static const std::string strDiscNotObject =
      "{\"discovery\":[\"SELECT * FROM time\"]}";
  static const std::string strDiscNoQuery =
      "{\"discovery\":{\"X1\":\"SELECT * FROM time\"}}";

  auto vec = std::vector<const std::string>({strQueryEmpty,
                                             strQueryNotObject,
                                             strQueryIntId,
                                             strQueryNegativeAccel,
                                             strQueryAccelLong,
                                             strDiscNotObject,
                                             strDiscNoQuery});

  startServer();

  if (!EnableMockDistPlugin()) {
    return;
  }

  for (auto& strQuery : vec) {
    MockDistributedClearWrites();

    auto status = MockDistributedSetReadValue(strQuery);
    EXPECT_TRUE(status.ok());

    auto dist = Distributed();

    status = dist.pullUpdates();
    // EXPECT_FALSE(status.ok()); // only invalid queries fails parse

    status = dist.runQueries();
    EXPECT_TRUE(status.ok());

    EXPECT_EQ(1U, dist.numDistReads());
    EXPECT_EQ(0U, dist.numDistWrites());
  }
}

TEST_F(DistributedTests, intra_sleep) {
  static const std::string strQuery =
      "{\"queries\":{\"D1\":\"SELECT year FROM time\", \"D2\":\"SELECT day "
      "FROM time\", \"D3\":\"SELECT timestamp FROM time\"}}";
  startServer();

  FLAGS_distributed_intra_sleep = 1;
  auto t1 = getUnixTime();
  if (!EnableMockDistPlugin()) {
    return;
  }

  auto status = MockDistributedSetReadValue(strQuery);
  EXPECT_TRUE(status.ok());

  auto dist = Distributed();

  status = dist.pullUpdates();
  EXPECT_TRUE(status.ok());

  status = dist.runQueries();
  EXPECT_TRUE(status.ok());

  auto t2 = getUnixTime();

  auto delta = t2 - t1;
  EXPECT_TRUE(delta >= 2);

  EXPECT_EQ(1U, dist.numDistReads());
  EXPECT_EQ(1U, dist.numDistWrites());
}

} // namespace osquery
