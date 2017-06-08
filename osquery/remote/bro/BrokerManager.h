/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <algorithm>
#include <iostream>
#include <list>
#include <memory>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <osquery/database.h>
#include <osquery/status.h>
#include <osquery/system.h>

namespace osquery {

class BrokerManager : private boost::noncopyable {
 private:
  BrokerManager() {
    // Set Broker UID
    std::string ident;
    auto status_huuid = getHostUUID(ident);
    if (status_huuid.ok()) {
      setNodeID(ident);
    }
    const auto& uid = getNodeID();

    // Create Broker endpoint
    Status s_ep = createEndpoint(uid);
    if (!s_ep.ok()) {
      LOG(ERROR) << "Failed to create broker endpoint";
      throw std::runtime_error{"Broker endpoint cannot be created"};
    }
  }

 public:
  /// Get a singleton instance of the BrokerManager class;
  static BrokerManager& get() {
    static BrokerManager bm;
    return bm;
  }

  // Topic Prefix
  const std::string TOPIC_PREFIX = "/bro/osquery/";
  const std::string TOPIC_ALL = TOPIC_PREFIX + "all";
  const std::string TOPIC_ANNOUNCE = TOPIC_PREFIX + "announce";
  const std::string TOPIC_PRE_INDIVIDUALS = TOPIC_PREFIX + "uid/";
  const std::string TOPIC_PRE_GROUPS = TOPIC_PREFIX + "group/";
  const std::string TOPIC_PRE_CUSTOMS = TOPIC_PREFIX + "custom/";

  // Event messages
  const std::string EVENT_HOST_NEW = "osquery::host_new";
  const std::string EVENT_HOST_JOIN = "osquery::host_join";
  const std::string EVENT_HOST_LEAVE = "osquery::host_leave";
  const std::string EVENT_HOST_EXECUTE = "osquery::host_execute";
  const std::string EVENT_HOST_SUBSCRIBE = "osquery::host_subscribe";
  const std::string EVENT_HOST_UNSUBSCRIBE = "osquery::host_unsubscribe";

 private:
  Status setNodeID(const std::string& uid);

  Status createEndpoint(const std::string& ep_name);

  Status unpeer();

 public:
  Status reset(bool groups_only = true);

  std::string getNodeID();

  Status addGroup(const std::string& group);

  Status removeGroup(const std::string& group);

  std::vector<std::string> getGroups();

  Status createMessageQueue(const std::string& topic);

  Status deleteMessageQueue(const std::string& topic);

  std::shared_ptr<broker::message_queue> getMessageQueue(
      const std::string& topic);

  std::vector<std::string> getTopics();

  Status peerEndpoint(const std::string& ip, int port, int timeout = -1);

  Status getOutgoingConnectionStatusChange(bool block = false);

  // Status getIncomingConnectionStatus();

  // Status joinExistingGroups();

  Status announce();

  int getOutgoingConnectionFD();

  Status logQueryLogItemToBro(const QueryLogItem& qli);

  Status sendEvent(const std::string& topic, const broker::message& msg);

 private:
  // The peering to identify the broker remote endpoint
  std::unique_ptr<broker::peering> p_ = nullptr;

  // The ID identifying the node (private channel)
  std::string nodeID_ = "";
  // The groups of the node
  std::vector<std::string> groups_;
  // The Broker Endpoint
  std::unique_ptr<broker::endpoint> ep_ = nullptr;

  //  Key: topic_Name, Value: message_queue
  std::map<std::string, std::shared_ptr<broker::message_queue>> messageQueues_;

 private:
  friend class BrokerManagerTests;
  FRIEND_TEST(BrokerManagerTests, test_reset);
};
}
