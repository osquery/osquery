/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <poll.h>

#include <gtest/gtest.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/remote/bro/broker_manager.h"

DECLARE_string(bro_ip);
DECLARE_uint64(bro_port);
DECLARE_string(bro_groups);
DECLARE_bool(disable_bro);

namespace osquery {

class BrokerManagerTests : public testing::Test {
 public:
  BrokerManagerTests() {
    broker::init();
    BrokerManager::get().reset(false);
    BrokerManager::get().unpeer();
  }

 protected:
  void SetUp() {
    Flag::updateValue("disable_bro", "false");

    //

    ep_ = std::make_unique<broker::endpoint>("brokermanager_test");
  }

  void TearDown() {}

 protected:
  BrokerManager& get() {
    return BrokerManager::get();
  }

 protected:
  std::unique_ptr<broker::endpoint> ep_ = nullptr;
};

void waitForMessage(int fd) {
  pollfd pfd{fd, POLLIN, 0};
  int poll_code = poll(&pfd, 1, 2);
  EXPECT_TRUE(poll_code >= 0);
}

TEST_F(BrokerManagerTests, test_failestablishconnection) {
  // NOT preparing receiver

  auto s_peer = get().peerEndpoint("127.0.0.1", 9999, 3);

  EXPECT_FALSE(s_peer.ok());
}

TEST_F(BrokerManagerTests, test_successestablishconnection) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen(9999, "127.0.0.1"));
  broker::message_queue test_queue(get().TOPIC_ANNOUNCE, *ep_);

  // Connect the broker endpoint
  auto s_peer = get().peerEndpoint("127.0.0.1", 9999, 3);
  EXPECT_TRUE(s_peer.ok());
}

TEST_F(BrokerManagerTests, test_announce) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen(9998, "127.0.0.1"));
  broker::message_queue test_queue(get().TOPIC_ANNOUNCE, *ep_);

  // Add groups - Part of the announcement
  EXPECT_TRUE(get().addGroup("test1").ok());
  EXPECT_TRUE(get().addGroup("test2").ok());

  // Connect the broker endpoint and send announcement
  auto s_peer = get().peerEndpoint("127.0.0.1", 9998, 3);
  EXPECT_TRUE(s_peer.ok());
  EXPECT_TRUE(get().announce().ok());

  // Wait for message
  waitForMessage(test_queue.fd());
  auto msgs = test_queue.want_pop();

  // Exactly one message expected
  EXPECT_TRUE(msgs.size() == 1);
  auto msg = msgs.front();

  // Checking announce message format
  EXPECT_TRUE(msg.size() == 3);
  // EVENT Name
  EXPECT_TRUE(broker::is<std::string>(msg[0]));
  EXPECT_TRUE(*broker::get<std::string>(msg[0]) == get().EVENT_HOST_NEW);
  // Node ID
  EXPECT_TRUE(broker::is<std::string>(msg[1]));
  std::string ident;
  getHostUUID(ident);
  EXPECT_TRUE(*broker::get<std::string>(msg[1]) == ident);
  // Group List
  EXPECT_TRUE(broker::is<broker::vector>(msg[2]));
  broker::vector groups = *broker::get<broker::vector>(msg[2]);
  EXPECT_TRUE(groups.size() == 2);
  EXPECT_TRUE(*broker::get<std::string>(groups.at(0)) == "test1");
  EXPECT_TRUE(*broker::get<std::string>(groups.at(1)) == "test2");
}

TEST_F(BrokerManagerTests, test_addandremovegroups) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen(9997, "127.0.0.1"));

  // Add group1 prior to connect
  EXPECT_TRUE(get().addGroup("test1").ok());

  // Connect the broker endpoint
  auto s_peer = get().peerEndpoint("127.0.0.1", 9997, 3);
  EXPECT_TRUE(s_peer.ok());

  // Add group2 after connecting
  EXPECT_TRUE(get().addGroup("test2").ok());

  // Expect subscription to both groups
  EXPECT_TRUE(get().getGroups().size() == 2);
  EXPECT_TRUE(get().getTopics().size() == 2);

  std::shared_ptr<broker::message_queue> mq1 =
      get().getMessageQueue(get().TOPIC_PRE_GROUPS + "test1");
  std::shared_ptr<broker::message_queue> mq2 =
      get().getMessageQueue(get().TOPIC_PRE_GROUPS + "test2");

  // Create and send messages to both groups
  broker::message test_msg1 = broker::message{broker::data("message1")};
  broker::message test_msg2 = broker::message{broker::data("message2")};
  EXPECT_TRUE(
      get().sendEvent(get().TOPIC_PRE_GROUPS + "test1", test_msg1).ok());
  EXPECT_TRUE(
      get().sendEvent(get().TOPIC_PRE_GROUPS + "test2", test_msg2).ok());

  // Receive messages on both groups
  waitForMessage(mq1->fd());
  waitForMessage(mq2->fd());
  auto msgs1 = mq1->want_pop();
  auto msgs2 = mq2->want_pop();

  // Exactly one message expected per group
  EXPECT_TRUE(msgs1.size() == 1);
  EXPECT_TRUE(msgs2.size() == 1);
  auto msg1 = msgs1.front();
  auto msg2 = msgs2.front();
  // Match message content
  EXPECT_TRUE(*broker::get<std::string>(msg1[0]) == "message1");
  EXPECT_TRUE(*broker::get<std::string>(msg2[0]) == "message2");

  // remove group2
  EXPECT_TRUE(get().removeGroup("test2").ok());

  // Expect subscription to group1 only
  EXPECT_TRUE(get().getGroups().size() == 1);
  EXPECT_TRUE(get().getGroups().at(0) == "test1");
  EXPECT_TRUE(get().getTopics().size() == 1);
  EXPECT_TRUE(get().getTopics().at(0) == get().TOPIC_PRE_GROUPS + "test1");

  // Create and send messages to both groups
  broker::message test_msg3 = broker::message{broker::data("message3")};
  broker::message test_msg4 = broker::message{broker::data("message4")};
  EXPECT_TRUE(
      get().sendEvent(get().TOPIC_PRE_GROUPS + "test1", test_msg3).ok());
  EXPECT_TRUE(
      get().sendEvent(get().TOPIC_PRE_GROUPS + "test2", test_msg4).ok());

  // Receive messages on group1
  waitForMessage(mq1->fd());
  auto conn_status = ep_->outgoing_connection_status().want_pop();
  auto msgs3 = mq1->want_pop();

  // Exactly one message expected on group1
  EXPECT_TRUE(msgs3.size() == 1);
  auto msg3 = msgs3.front();
  // Match message content
  EXPECT_TRUE(*broker::get<std::string>(msg3[0]) == "message3");

  // remove group1
  EXPECT_TRUE(get().removeGroup("test1").ok());

  // Expect subscription to no group
  EXPECT_NE(get().getNodeID(), "");
  EXPECT_TRUE(get().getGroups().size() == 0);
  EXPECT_TRUE(get().getTopics().size() == 0);
}

TEST_F(BrokerManagerTests, test_reset) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen(9996, "127.0.0.1"));
  // broker::message_queue test_queue(get().TOPIC_ANNOUNCE, *ep_);

  // Subscribe to all and individual topic
  EXPECT_TRUE(get().createMessageQueue(get().TOPIC_ALL).ok());
  EXPECT_TRUE(
      get()
          .createMessageQueue(get().TOPIC_PRE_INDIVIDUALS + get().getNodeID())
          .ok());

  // Add group1 prior to connect
  EXPECT_TRUE(get().addGroup("test1").ok());

  // Connect the broker endpoint
  auto s_peer = get().peerEndpoint("127.0.0.1", 9996, 3);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Add group2 after connecting
  EXPECT_TRUE(get().addGroup("test2").ok());

  get().reset(false);

  // Expect reset
  EXPECT_NE(get().nodeID_, "");
  EXPECT_TRUE(get().groups_.size() == 0);
  EXPECT_TRUE(get().messageQueues_.size() == 0);
  EXPECT_NE(get().ep_, nullptr);
}

TEST_F(BrokerManagerTests, test_logQueryLogItemToBro) {
  // TODO: test logging for QueryLogItem
}
}