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

#include <algorithm>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/bro/QueryManager.h"

DECLARE_string(bro_ip);
DECLARE_uint64(bro_port);
DECLARE_string(bro_groups);
DECLARE_bool(disable_bro);

namespace osquery {

class QueryManagerTests : public testing::Test {
 public:
  QueryManagerTests() {
    QueryManager::get().reset();
  }

 protected:
  void SetUp() {
    Flag::updateValue("disable_bro", "false");
  }

  void TearDown() {}

 protected:
  QueryManager& get() {
    return QueryManager::get();
  }

 protected:
};

TEST_F(QueryManagerTests, test_queriesadd) {
  // Add OneTime Query
  SubscriptionRequest sr_ot;
  sr_ot.query = "SELECT hello FROM world";
  sr_ot.response_event = "response_event1";
  sr_ot.response_topic = "response_topic1";
  sr_ot.cookie = "yummie";
  EXPECT_TRUE(get().addOneTimeQueryEntry(sr_ot) != "");

  // Add Schedule Query
  SubscriptionRequest sr_s;
  sr_s.query = "SELECT alan FROM turing";
  sr_s.response_event = "response_event2";
  sr_s.response_topic = "response_topic2";
  sr_s.cookie = "monster";
  EXPECT_TRUE(get().addScheduleQueryEntry(sr_s).ok());

  // Add OneTime Query2
  SubscriptionRequest sr_ot2;
  sr_ot2.query = "SELECT uni FROM hamburg";
  sr_ot2.response_event = "response_event3";
  sr_ot2.response_topic = "response_topic3";
  sr_ot2.cookie = "Sesamstraße";
  std::string newID_ot2 = get().addOneTimeQueryEntry(sr_ot2);
  EXPECT_TRUE(newID_ot2 != "");

  // Expect 3 queries
  EXPECT_TRUE(get().getQueryIDs().size() == 3);
  std::string queryID_ot = get().findIDForQuery(sr_ot.query);
  std::string queryID_s = get().findIDForQuery(sr_s.query);
  std::string queryID_ot2 = get().findIDForQuery(sr_ot2.query);

  EXPECT_TRUE(queryID_ot != queryID_s);
  EXPECT_TRUE(queryID_ot2 != queryID_s);

  EXPECT_TRUE(std::find(get().getQueryIDs().begin(),
                        get().getQueryIDs().end(),
                        queryID_ot) != get().getQueryIDs().end());
  EXPECT_TRUE(std::find(get().getQueryIDs().begin(),
                        get().getQueryIDs().end(),
                        queryID_s) != get().getQueryIDs().end());
  EXPECT_TRUE(std::find(get().getQueryIDs().begin(),
                        get().getQueryIDs().end(),
                        queryID_ot2) != get().getQueryIDs().end());

  std::string qType;
  std::string query;
  // Test sr_ot
  EXPECT_TRUE(get().findQueryAndType(queryID_ot, qType, query).ok());
  EXPECT_EQ(query, sr_ot.query);
  EXPECT_EQ(qType, "ONETIME");
  EXPECT_EQ(get().getEventCookie(queryID_ot), sr_ot.cookie);
  EXPECT_EQ(get().getEventName(queryID_ot), sr_ot.response_event);
  EXPECT_EQ(get().getEventTopic(queryID_ot), sr_ot.response_topic);

  // Test sr_s
  EXPECT_TRUE(get().findQueryAndType(queryID_s, qType, query).ok());
  EXPECT_EQ(query, sr_s.query);
  EXPECT_EQ(qType, "SCHEDULE");
  EXPECT_EQ(get().getEventCookie(queryID_s), sr_s.cookie);
  EXPECT_EQ(get().getEventName(queryID_s), sr_s.response_event);
  EXPECT_EQ(get().getEventTopic(queryID_s), sr_s.response_topic);

  // Test sr_ot2
  EXPECT_TRUE(get().findQueryAndType(queryID_ot2, qType, query).ok());
  EXPECT_EQ(query, sr_ot2.query);
  EXPECT_EQ(qType, "ONETIME");
  EXPECT_EQ(get().getEventCookie(queryID_ot2), sr_ot2.cookie);
  EXPECT_EQ(get().getEventName(queryID_ot2), sr_ot2.response_event);
  EXPECT_EQ(get().getEventTopic(queryID_ot2), sr_ot2.response_topic);
  EXPECT_TRUE(get().findIDForQuery(sr_ot2.query) == newID_ot2);
}

TEST_F(QueryManagerTests, test_queriesremove) {
  // Add OneTime Query
  SubscriptionRequest sr_ot;
  sr_ot.query = "SELECT hello FROM world";
  sr_ot.response_event = "response_event1";
  sr_ot.response_topic = "response_topic1";
  sr_ot.cookie = "yummie";
  get().addOneTimeQueryEntry(sr_ot);
  std::string queryID_ot = get().findIDForQuery(sr_ot.query);

  // Add Schedule Query
  SubscriptionRequest sr_s;
  sr_s.query = "SELECT alan FROM turing";
  sr_s.response_event = "response_event2";
  sr_s.response_topic = "response_topic2";
  sr_s.cookie = "monster";
  get().addScheduleQueryEntry(sr_s);
  std::string queryID_s = get().findIDForQuery(sr_s.query);

  // Add OneTime Query2
  SubscriptionRequest sr_ot2;
  sr_ot2.query = "SELECT uni FROM hamburg";
  sr_ot2.response_event = "response_event3";
  sr_ot2.response_topic = "response_topic3";
  sr_ot2.cookie = "Sesamstraße";
  get().addOneTimeQueryEntry(sr_ot2);
  std::string queryID_ot2 = get().findIDForQuery(sr_ot2.query);

  // Remove sr_s and sr_ot2
  get().removeQueryEntry(sr_s.query);
  get().removeQueryEntry(sr_ot2.query);

  // Expect 1 query
  EXPECT_TRUE(get().getQueryIDs().size() == 1);
  EXPECT_TRUE(std::find(get().getQueryIDs().begin(),
                        get().getQueryIDs().end(),
                        queryID_ot) != get().getQueryIDs().end());

  std::string qType;
  std::string query;
  // Test sr_ot
  EXPECT_TRUE(get().findQueryAndType(queryID_ot, qType, query).ok());
  EXPECT_EQ(query, sr_ot.query);
  EXPECT_EQ(qType, "ONETIME");
  EXPECT_EQ(get().getEventCookie(queryID_ot), sr_ot.cookie);
  EXPECT_EQ(get().getEventName(queryID_ot), sr_ot.response_event);
  EXPECT_EQ(get().getEventTopic(queryID_ot), sr_ot.response_topic);

  // Remove sr_ot
  get().removeQueryEntry(sr_ot.query);

  // Expect 0 queries
  EXPECT_TRUE(get().getQueryIDs().size() == 0);
  EXPECT_THROW(get().getEventCookie(queryID_ot), std::out_of_range);
  EXPECT_THROW(get().getEventName(queryID_ot), std::out_of_range);
  EXPECT_THROW(get().getEventTopic(queryID_ot), std::out_of_range);
}

TEST_F(QueryManagerTests, test_reset) {
  // Add OneTime Query
  SubscriptionRequest sr_ot;
  sr_ot.query = "SELECT hello FROM world";
  sr_ot.response_event = "response_event1";
  sr_ot.response_topic = "response_topic1";
  sr_ot.cookie = "yummie";
  EXPECT_TRUE(get().addOneTimeQueryEntry(sr_ot) != "");

  // Add Schedule Query
  SubscriptionRequest sr_s;
  sr_s.query = "SELECT alan FROM turing";
  sr_s.response_event = "response_event2";
  sr_s.response_topic = "response_topic2";
  sr_s.cookie = "monster";
  EXPECT_TRUE(get().addScheduleQueryEntry(sr_s).ok());

  // Expect 2 queries
  EXPECT_TRUE(get().getQueryIDs().size() == 2);

  // Reset
  Status s_reset = get().reset();
  EXPECT_TRUE(s_reset.ok());

  EXPECT_TRUE(get().getQueryIDs().size() == 0);
}

TEST_F(QueryManagerTests, test_getQueryConfigString) {
  // TODO: getQueryConfigString
}
}