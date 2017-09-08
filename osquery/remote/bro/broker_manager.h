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

/**
 * @brief Manager class for connections of the broker communication library.
 *
 * The BrokerManager is a singleton to keep track of broker communications and
 * to communicate via the broker endpoint. It provides various ways to retrieve
 * and modify connections. Each 'connection' is technically a subscription to a
 * topic in the publish-subscribe communication.
 *
 * One message_queue (i.e. message inbox) is created for each subscribed topic.
 * Among some predefined topics, joining a group results in subscribing the
 * corresponding topic to receive messages addressed for this group.
 */
class BrokerManager : private boost::noncopyable {
 private:
  /**
   * @brief The private constructor of the class.
   *
   * The initial setup includes to adapt the osquery HostUUID for identifying
   * the new broker endpoint.
   */
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

  // Broker Topic Prefix
  const std::string TOPIC_PREFIX = "/bro/osquery/";
  const std::string TOPIC_ALL = TOPIC_PREFIX + "all";
  const std::string TOPIC_ANNOUNCE = TOPIC_PREFIX + "announce";
  const std::string TOPIC_PRE_INDIVIDUALS = TOPIC_PREFIX + "uid/";
  const std::string TOPIC_PRE_GROUPS = TOPIC_PREFIX + "group/";
  const std::string TOPIC_PRE_CUSTOMS = TOPIC_PREFIX + "custom/";

  // broker Event Messages
  const std::string EVENT_HOST_NEW = "osquery::host_new";
  const std::string EVENT_HOST_JOIN = "osquery::host_join";
  const std::string EVENT_HOST_LEAVE = "osquery::host_leave";
  const std::string EVENT_HOST_EXECUTE = "osquery::host_execute";
  const std::string EVENT_HOST_SUBSCRIBE = "osquery::host_subscribe";
  const std::string EVENT_HOST_UNSUBSCRIBE = "osquery::host_unsubscribe";

 private:
  /// Set a node ID if not already exists
  Status setNodeID(const std::string& uid);

  /// Create a new broker endpoint
  Status createEndpoint(const std::string& ep_name);

  /// Unpeer from existing remote broker endpoint
  Status unpeer();

 public:
  /**
   * @brief Reset the BrokerManager to its initial state.
   *
   * This makes the BrokerManager to remove all groups and therefore unsubscribe
   * from all respective broker topics.
   *
   * @param groups_only Should one unsubscribe from groups only or additionally
   * also from predefined topics
   * @return
   */
  Status reset(bool groups_only = true);

  /// Get the ID of broker endpoint that this osquery hosts uses
  std::string getNodeID();

  /**
   * @brief Make the osquery host to join a group.
   *
   * Joining a group results in subscribing to the broker topic identified by
   * 'TOPIC_PRE_GROUPS + group'
   *
   * @param group the name of the group to join
   * @return
   */
  Status addGroup(const std::string& group);

  /**
   * @brief Make the osquery host to leave a group.
   *
   * Leaving a group results in unsubscribing from the broker topic identified
   * by 'TOPIC_PRE_GROUPS + group'
   *
   * @param group the name of the group to leave
   * @return
   */
  Status removeGroup(const std::string& group);

  /// Get the groups that the osquery host has joined
  std::vector<std::string> getGroups();

  /// Subscribe to the topic
  Status createMessageQueue(const std::string& topic);

  /// Unsubscribe from the topic
  Status deleteMessageQueue(const std::string& topic);

  /// Get the message_queue (i.e. subscription message inbox) of the topic
  std::shared_ptr<broker::message_queue> getMessageQueue(
      const std::string& topic);

  /// Get all subscribed topics
  std::vector<std::string> getTopics();

  /**
   * @brief Establish the connection to a remote broker endpoint.
   *
   * Peering with another broker endpoint enables broker overlay communication.
   * It provides the basic connectivity for communication.
   *
   * @param ip the ip address of the remote endpoint
   * @param port the port of the remote endpoint
   * @param timeout duration to wait before the peering attemp times out.
   * Negativ value for blocking until connection is established.
   * @return
   */
  Status peerEndpoint(const std::string& ip, int port, int timeout = -1);

  /**
   * @brief Check if the status of basic connectivity (i.e. peering) changed.
   *
   * This indicates that the osquery host became connected or disconnected.
   *
   * @param status the latest peering status change (if any)
   * @param block if true, in case no change occurred the call blocks until a
   * change happens
   * @return Failure if no change happened (only possible for non-blocking call)
   */
  Status getOutgoingConnectionStatusChange(
      broker::outgoing_connection_status::tag& status, bool block = false);

  /**
   * @brief Make the osquery host to announce itself to the remote broker
   * endpoint.
   *
   * This broker message includes the hosts nodeID, groups and network
   * interfaces
   *
   * @return
   */
  Status announce();

  /// Get the file descriptor for peering to detection changes of connection
  /// status
  int getOutgoingConnectionFD();

  /// Send each entry in the QueryLogItem as broker event
  Status logQueryLogItemToBro(const QueryLogItem& qli);

  /// Send the broker message to a specific topic
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
