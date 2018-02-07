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

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

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
  BrokerManagerTests() {}

 protected:
  void SetUp() {
    LOG(INFO) << "Calling SetUp()";
    Flag::updateValue("disable_bro", "false");
    Flag::updateValue("bro_ip", "172.0.0.1");
    Flag::updateValue("bro_port", "0");
    Flag::updateValue("bro_groups", "{\"group1\":\"test1\"}");

    // Create listening endpoint
    std::string ep_name = "brokermanager_test";
    ep_ = std::make_unique<broker::endpoint>();
  }

  void TearDown() {
    LOG(INFO) << "Calling TearDown()";
    Status s;
    s = BrokerManager::get().reset(false);
    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
    }
    s = BrokerManager::get().unpeer();
    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
    }
  }

 protected:
  BrokerManager& get() {
    return BrokerManager::get();
  }

 protected:
  std::unique_ptr<broker::endpoint> ep_ = nullptr;
};

void waitForMessage(int fd, bool expectMsg = true) {
  pollfd pfd{fd, POLLIN, 0};
  int poll_code = poll(&pfd, 1, 2 * 1000);
  if (expectMsg) {
    EXPECT_GT(poll_code, 0);
  } else {
    EXPECT_EQ(poll_code, 0);
  }
}

TEST_F(BrokerManagerTests, test_failestablishconnection) {
  // NOT preparing receiver
  get().remote_endpoint_ = std::pair<std::string, int>{"127.0.0.1", 9999};
  auto s_peer = get().checkConnection(3);
  EXPECT_FALSE(s_peer.ok());
}

TEST_F(BrokerManagerTests, test_successestablishconnection) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9999));
  broker::subscriber test_queue = ep_->make_subscriber({get().TOPIC_ANNOUNCE});

  // Connect the broker endpoint
  LOG(WARNING) << "Peering Endpoint";
  get().remote_endpoint_ = std::pair<std::string, int>{"127.0.0.1", 9999};
  auto s_peer = get().checkConnection(3);
  LOG(WARNING) << "Checking Peering Endpoint";
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }
  LOG(INFO) << "Number of peers: " << get().ep_->peers().size();
}

TEST_F(BrokerManagerTests, test_announce) {
  LOG(INFO) << "Number of peers: " << get().ep_->peers().size();
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9997));
  broker::subscriber announce_queue =
      ep_->make_subscriber({get().TOPIC_ANNOUNCE});

  // Add groups - Part of the announcement
  // For initial groups see SetUp()

  // Connect the broker endpoint and send announcement
  get().remote_endpoint_ = std::pair<std::string, int>{"127.0.0.1", 9997};
  auto s_peer = get().checkConnection(3);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Wait for message
  waitForMessage(announce_queue.fd());
  // Exactly one message expected
  EXPECT_EQ(announce_queue.available(), 1ul);
  auto msg = announce_queue.get(broker::to_duration(3)).value();
  LOG(INFO) << "Topic: " << msg.first.string();
  broker::bro::Event event(msg.second);

  // EVENT Name
  EXPECT_FALSE(event.name().empty());
  EXPECT_EQ(event.name(), get().EVENT_HOST_NEW);
  LOG(INFO) << "Event Name: " << event.name();

  auto event_args = event.args();
  // Checking announce message format
  LOG(INFO) << "Event Args: " << broker::to_string(event_args);
  EXPECT_EQ(event_args.size(), 2ul);

  // Node ID
  std::string ident;
  getHostUUID(ident);
  EXPECT_TRUE(broker::is<std::string>(event_args[0]));
  EXPECT_EQ(broker::get<std::string>(event_args[0]), ident);
  // Group List
  EXPECT_TRUE(broker::is<broker::vector>(event_args[1]));
  broker::vector groups = broker::get<broker::vector>(event_args[1]);
  EXPECT_EQ(groups.size(), 1ul);
  EXPECT_EQ(broker::get<std::string>(groups.at(0)), "test1");
}

TEST_F(BrokerManagerTests, test_addandremovegroups) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9996));
  broker::subscriber announce_queue =
      ep_->make_subscriber({get().TOPIC_ANNOUNCE});

  // Add group1 prior to connect
  // For initial groups see SetUp()

  // Connect the broker endpoint
  get().remote_endpoint_ = std::pair<std::string, int>{"127.0.0.1", 9996};
  auto s_peer = get().checkConnection(3);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Add group2 after connecting
  EXPECT_TRUE(get().addGroup("test2").ok());
  // Wait for announce message
  waitForMessage(announce_queue.fd());

  // Expect subscription to both groups
  EXPECT_EQ(get().getGroups().size(), 2ul);
  // Individual + All + 2 Groups
  EXPECT_EQ(get().getTopics().size(), 4ul);

  // Create and send messages to both groups
  broker::bro::Event test_msg1("ev_name1", {"message1"});
  broker::bro::Event test_msg2("ev_name2", {"message2"});
  ep_->publish(get().TOPIC_PRE_GROUPS + "test1", test_msg1);
  ep_->publish(get().TOPIC_PRE_GROUPS + "test2", test_msg2);

  // Receive messages on both groups
  std::shared_ptr<broker::subscriber> sub1 =
      get().getSubscriber(get().TOPIC_PRE_GROUPS + "test1");
  std::shared_ptr<broker::subscriber> sub2 =
      get().getSubscriber(get().TOPIC_PRE_GROUPS + "test2");
  waitForMessage(sub1->fd());
  waitForMessage(sub2->fd());
  // Exactly one message expected per group
  EXPECT_EQ(sub1->available(), 1ul);
  EXPECT_EQ(sub2->available(), 1ul);
  auto msg1 = sub1->get(broker::to_duration(3)).value();
  auto msg2 = sub2->get(broker::to_duration(3)).value();

  broker::bro::Event event1(msg1.second);
  broker::bro::Event event2(msg2.second);
  // Match message content
  EXPECT_EQ(event1.name(), "ev_name1");
  EXPECT_EQ(event2.name(), "ev_name2");
  broker::vector event1_args = event1.args();
  broker::vector event2_args = event2.args();
  EXPECT_EQ(event1_args.size(), 1ul);
  EXPECT_EQ(broker::get<std::string>(event1_args[0]), "message1");
  EXPECT_EQ(event2_args.size(), 1ul);
  EXPECT_EQ(broker::get<std::string>(event2_args[0]), "message2");

  // remove group2
  LOG(INFO) << "Removing Group 2";
  EXPECT_TRUE(get().removeGroup("test2").ok());
  // Wait for the unsubscription to be propagated
  sleepFor(1 * 1000);

  // Expect subscription to group1 only
  EXPECT_EQ(get().getGroups().size(), 1ul);
  EXPECT_EQ(get().getGroups().at(0), "test1");
  EXPECT_EQ(get().getTopics().size(), 3ul);
  EXPECT_NE(std::find(get().getTopics().begin(),
                      get().getTopics().end(),
                      get().TOPIC_PRE_GROUPS + "test1"),
            get().getTopics().end());
  EXPECT_NE(std::find(get().getTopics().begin(),
                      get().getTopics().end(),
                      get().TOPIC_PRE_INDIVIDUALS + get().getNodeID()),
            get().getTopics().end());
  EXPECT_NE(
      std::find(
          get().getTopics().begin(), get().getTopics().end(), get().TOPIC_ALL),
      get().getTopics().end());

  // Create and send messages to both groups
  broker::bro::Event test_msg3("ev_name3", {"message3"});
  broker::bro::Event test_msg4("ev_name4", {"message4"});
  ep_->publish(get().TOPIC_PRE_GROUPS + "test1", test_msg3);
  ep_->publish(get().TOPIC_PRE_GROUPS + "test2", test_msg4);

  // Receive messages on group1
  waitForMessage(sub1->fd());
  // TODO: How to revoke the subscription of removed groups
  // waitForMessage(sub2->fd(), false);
  // Exactly one message expected on group1
  EXPECT_EQ(sub1->available(), 1ul);
  get().getPeeringStatus();
  auto msg3 = sub1->get(broker::to_duration(3)).value();

  broker::bro::Event event3(msg3.second);
  // Match message content
  EXPECT_EQ(event3.name(), "ev_name3");
  EXPECT_EQ(event3.args().size(), 1ul);
  EXPECT_EQ(broker::get<std::string>(event3.args()[0]), "message3");

  // remove group1
  EXPECT_TRUE(get().removeGroup("test1").ok());

  // Expect subscription to no group
  EXPECT_NE(get().getNodeID(), "");
  EXPECT_EQ(get().getGroups().size(), 0ul);
  EXPECT_EQ(get().getTopics().size(), 2ul);
}

TEST_F(BrokerManagerTests, test_reset) {
  // Prepare receiver
  EXPECT_TRUE(ep_->listen("127.0.0.1", 9995));
  // broker::message_queue test_queue(get().TOPIC_ANNOUNCE, *ep_);

  // Subscribe to all and individual topic
  EXPECT_TRUE(get().createSubscriber(get().TOPIC_ALL).ok());
  EXPECT_TRUE(
      get()
          .createSubscriber(get().TOPIC_PRE_INDIVIDUALS + get().getNodeID())
          .ok());

  // Add group1 prior to connect
  EXPECT_TRUE(get().addGroup("test1").ok());

  // Connect the broker endpoint
  get().remote_endpoint_ = std::pair<std::string, int>{"127.0.0.1", 9995};
  auto s_peer = get().checkConnection(3);
  EXPECT_TRUE(s_peer.ok());
  if (not s_peer.ok()) {
    LOG(ERROR) << s_peer.getMessage();
  }

  // Add group2 after connecting
  EXPECT_TRUE(get().addGroup("test2").ok());

  get().reset(false);

  // Expect reset
  EXPECT_NE(get().nodeID_, "");
  EXPECT_EQ(get().groups_.size(), 0ul);
  EXPECT_EQ(get().subscribers_.size(), 0ul);
  EXPECT_NE(get().ep_, nullptr);
  EXPECT_NE(get().ss_, nullptr);

  get().unpeer();

  // Expect reset
  EXPECT_NE(get().ep_, nullptr);
  EXPECT_EQ(get().ss_, nullptr);
}

TEST_F(BrokerManagerTests, test_logQueryLogItemToBro) {
  // TODO: test logging for QueryLogItem
}
}