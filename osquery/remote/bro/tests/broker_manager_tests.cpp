/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <poll.h>

#include <gtest/gtest.h>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/error.hh>
#include <broker/status.hh>
#include <broker/status_subscriber.hh>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/remote/bro/broker_manager.h"

DECLARE_string(bro_ip);
DECLARE_uint64(bro_port);
DECLARE_string(bro_groups);
DECLARE_bool(disable_bro);

namespace osquery {

class BrokerManagerTests : public testing::Test {
 public:
  BrokerManagerTests() {
    // Disconnect previous connection
    if (remote_endpoint_.first != "" || remote_endpoint_.second != 0) {
      if (get().ep_ != nullptr) {
        LOG(ERROR) << "get().ep_ is nullptr";
      }
      if (get().ss_ != nullptr) {
        LOG(ERROR) << "get().ss_ is nullptr";
      }
      get().ep_->unpeer(remote_endpoint_.first, remote_endpoint_.second);
      remote_endpoint_ = {"", 0};
    }

    // Reset previous connection
    get().ss_ = nullptr;
    get().connection_status_ = {};
    get().ep_ = nullptr;
    get().createEndpoint(get().getNodeID());
    // Remaining parameters are reset when BrokerManager connects

    // Create new endpoint for this test
    ep_ = std::make_unique<broker::endpoint>();
  }

 protected:
  void SetUp() {
    Flag::updateValue("disable_bro", "false");
  }

  void TearDown() {}

 protected:
  BrokerManager& get() {
    return BrokerManager::get();
  }

  void setRemoteEndpoint(const std::string& addr, int port) {
    remote_endpoint_ = {addr, port};
    get().remote_endpoint_ = remote_endpoint_;
  }

 protected:
  std::unique_ptr<broker::endpoint> ep_ = nullptr;
  std::pair<std::string, int> remote_endpoint_{"", 0};
};

void waitForMessage(int fd, bool expect=true) {
  pollfd pfd{fd, POLLIN, 0};
  int poll_code = poll(&pfd, 1, 3000);

  if (expect) {
    EXPECT_GT(poll_code, 0);
    if (poll_code > 0) {
      EXPECT_EQ((pfd.revents & POLLIN), POLLIN);
      EXPECT_NE((pfd.revents & POLLERR), POLLERR);
    }
  } else {
    if (poll_code > 0) {
      EXPECT_NE((pfd.revents & POLLIN), POLLIN);
      EXPECT_EQ((pfd.revents & POLLERR), POLLERR);
    }
  }
}

TEST_F(BrokerManagerTests, test_failestablishconnection) {
  // NOT preparing receiver

  setRemoteEndpoint("127.0.0.1", 9999);
  auto s_peer = get().checkConnection(5);

  EXPECT_FALSE(s_peer.ok());
}

TEST_F(BrokerManagerTests, test_successestablishconnection) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9999));
  broker::subscriber test_queue = ep_->make_subscriber({get().TOPIC_ANNOUNCE});

  // Connect the broker endpoint
  setRemoteEndpoint("127.0.0.1", 9999);
  auto s_peer = get().checkConnection(5);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }
}

TEST_F(BrokerManagerTests, test_announce) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9998));
  broker::subscriber test_queue = ep_->make_subscriber({get().TOPIC_ANNOUNCE});

  // Add groups - Part of the announcement
  get().startup_groups_ = {"test1", "test2"};

  // Connect the broker endpoint and send announcement
  setRemoteEndpoint("127.0.0.1", 9998);
  auto s_peer = get().checkConnection(5);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Wait for message
  waitForMessage(test_queue.fd());
  // Exactly one message expected
  EXPECT_EQ(test_queue.available(), 1UL);
  auto msg_full = test_queue.get();

  // Checking announce message format
  EXPECT_EQ(msg_full.first, get().TOPIC_ANNOUNCE);
  broker::bro::Event event(msg_full.second);
  EXPECT_EQ(event.name(), get().EVENT_HOST_NEW);
  auto msg = event.args();
  EXPECT_EQ(msg.size(), 2UL);
  // Node ID
  EXPECT_TRUE(broker::is<std::string>(msg[0]));
  std::string ident;
  getHostUUID(ident);
  EXPECT_EQ(broker::get<std::string>(msg[0]), ident);
  // Group List
  EXPECT_TRUE(broker::is<broker::vector>(msg[1]));
  broker::vector groups = broker::get<broker::vector>(msg[1]);
  EXPECT_EQ(groups.size(), 2UL);
  EXPECT_EQ(broker::get<std::string>(groups.at(0)), "test1");
  EXPECT_EQ(broker::get<std::string>(groups.at(1)), "test2");
}

TEST_F(BrokerManagerTests, test_addandremovegroups) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9997));

  // Add group1 prior to connect
  get().startup_groups_ = {"test1"};

  // Connect the broker endpoint
  setRemoteEndpoint("127.0.0.1", 9997);
  auto s_peer = get().checkConnection(5);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Add group2 after connecting
  EXPECT_TRUE(get().addGroup("test2").ok());
  // TODO: dirty fix for solving raise condition
  // Propagating new subscription takes too long
  sleepFor(1*1000);

  // Expect subscription to both groups (+2 default topics)
  EXPECT_EQ(get().getGroups().size(), 2UL);
  EXPECT_EQ(get().getTopics().size(), 4UL);


  std::shared_ptr<broker::subscriber> mq1 =
      get().getSubscriber(get().TOPIC_PRE_GROUPS + "test1");
  std::shared_ptr<broker::subscriber> mq2 =
      get().getSubscriber(get().TOPIC_PRE_GROUPS + "test2");

  // Create and send messages to both groups
  broker::bro::Event test_msg1("message1", {broker::data("data1")});
  broker::bro::Event test_msg2("message2", {broker::data("data2")});
  ep_->publish(get().TOPIC_PRE_GROUPS + "test1", test_msg1);
  ep_->publish(get().TOPIC_PRE_GROUPS + "test2", test_msg2);

  // Receive messages on both groups
  waitForMessage(mq1->fd());
  waitForMessage(mq2->fd());

  // Exactly one message expected per group
  EXPECT_EQ(mq1->available(), 1UL);
  EXPECT_EQ(mq2->available(), 1UL);
  auto msg1_full = mq1->get();
  auto msg2_full = mq2->get();

  // Check Format
  EXPECT_EQ(msg1_full.first, get().TOPIC_PRE_GROUPS + "test1");
  EXPECT_EQ(msg2_full.first, get().TOPIC_PRE_GROUPS + "test2");
  broker::bro::Event event1(msg1_full.second);
  broker::bro::Event event2(msg2_full.second);
  EXPECT_EQ(event1.name(), "message1");
  EXPECT_EQ(event2.name(), "message2");
  auto msg1 = event1.args();
  auto msg2 = event2.args();

  // Match message content
  EXPECT_EQ(msg1.size(), 1UL);
  EXPECT_EQ(msg2.size(), 1UL);
  EXPECT_EQ(broker::get<std::string>(msg1[0]), "data1");
  EXPECT_EQ(broker::get<std::string>(msg2[0]), "data2");

  // remove group2
  mq2.reset();
  EXPECT_TRUE(get().removeGroup("test2").ok());
  // TODO: dirty fix for solving raise condition
  // Propagating new subscription takes too long
  sleepFor(1*1000);

  // Expect subscription to group1 only (+2 default topics)
  EXPECT_EQ(get().getGroups().size(), 1UL);
  EXPECT_EQ(get().getGroups().at(0), "test1");
  const auto& topics = get().getTopics();
  EXPECT_EQ(topics.size(), 3UL);
  EXPECT_NE(std::find(topics.begin(), topics.end(), get().TOPIC_ALL), topics.end());
  EXPECT_NE(std::find(topics.begin(), topics.end(), get().TOPIC_PRE_INDIVIDUALS + get().getNodeID()), topics.end());
  EXPECT_NE(std::find(topics.begin(), topics.end(), get().TOPIC_PRE_GROUPS + "test1"), topics.end());
  const auto& subscribers = get().subscribers_;
  EXPECT_EQ(subscribers.size(), 3UL);
  EXPECT_NE(subscribers.find(get().TOPIC_ALL), subscribers.end());
  EXPECT_NE(subscribers.find(get().TOPIC_PRE_INDIVIDUALS + get().getNodeID()), subscribers.end());
  EXPECT_NE(subscribers.find(get().TOPIC_PRE_GROUPS + "test1"), subscribers.end());

  // Create and send messages to both groups
  broker::bro::Event test_msg3("message3", {broker::data("data3")});
  broker::bro::Event test_msg4("message4", {broker::data("data4")});
  ep_->publish(get().TOPIC_PRE_GROUPS + "test1", test_msg3);
  ep_->publish(get().TOPIC_PRE_GROUPS + "test2", test_msg4);

  // Receive messages on group1
  waitForMessage(mq1->fd());
  EXPECT_EQ(mq1->available(), 1UL);
  auto msg3_full = mq1->get();

  // Check Format
  EXPECT_EQ(msg3_full.first, get().TOPIC_PRE_GROUPS + "test1");
  broker::bro::Event event3(msg3_full.second);
  EXPECT_EQ(event3.name(), "message3");
  auto msg3 = event3.args();

  // Match message content
  EXPECT_EQ(broker::get<std::string>(msg3[0]), "data3");

  // remove group1
  EXPECT_TRUE(get().removeGroup("test1").ok());

  // Expect subscription to no group (+2 default topics)
  EXPECT_NE(get().getNodeID(), "");
  EXPECT_EQ(get().getGroups().size(), 0UL);
  EXPECT_EQ(get().getTopics().size(), 2UL);
}

TEST_F(BrokerManagerTests, test_reset) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9996));

  // Add group1 prior to connect
  get().startup_groups_ = {"test1"};

  // Connect the broker endpoint
  setRemoteEndpoint("127.0.0.1", 9996);
  auto s_peer = get().checkConnection(5);
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
  EXPECT_TRUE(get().subscribers_.size() == 0);
  EXPECT_NE(get().ep_, nullptr);
}

TEST_F(BrokerManagerTests, test_reconnect) {
  // Connect to unavailable endpoint
  setRemoteEndpoint("127.0.0.1", 9995);
  auto s_peer = get().checkConnection(5);
  EXPECT_FALSE(s_peer.ok());

  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9995));
  sleepFor(1*1000);
  s_peer = get().checkConnection(5);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Kill server
  ep_ = nullptr;
  sleepFor(1*1000);
  s_peer = get().checkConnection(5);
  EXPECT_FALSE(s_peer.ok());

  // Restart Server
  ep_ = std::make_unique<broker::endpoint>();
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9995));
  sleepFor(1*1000);
  s_peer = get().checkConnection(5);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }
}

TEST_F(BrokerManagerTests, test_logQueryLogItemToBro) {
  // TODO: test logging for QueryLogItem
}
} // namespace osquery