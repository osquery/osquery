/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <algorithm>
#include <iostream>
#include <list>
#include <memory>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/core.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include "osquery/remote/bro/bro_utils.h"

namespace osquery {

DECLARE_string(bro_ip);
DECLARE_uint64(bro_port);
DECLARE_string(bro_groups);

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
  BrokerManager();

 public:
  /// Get a singleton instance of the BrokerManager class;
  static BrokerManager& get();

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

  /// Initiates the peering to remote endpoint
  Status initiatePeering();

  /// Initiates the reset of the broker manager
  Status initiateReset(bool reset_schedule = true);

  /**
   * @brief Retrieve the latest connection status change
   *
   * Checks for any connection changes and updates cached status to the latest
   * change.
   * Returns the latest cached status if no change occurred within timeout
   *
   * @param timeout duration how long to wait for a status change
   * @return
   */
  std::pair<broker::status, bool> getPeeringStatus(long timeout = 0);

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
  Status createSubscriber(const std::string& topic);

  /// Unsubscribe from the topic
  Status deleteSubscriber(const std::string& topic);

  /// Get the message_queue (i.e. subscription message inbox) of the topic
  std::shared_ptr<broker::subscriber> getSubscriber(const std::string& topic);

  /// Get all subscribed topics
  std::vector<std::string> getTopics();

  /**
   * @brief checks for a working broker connection and wait if requested
   *
   * This is also used to initially establishing the connection and to reconnect
   * after failure
   *
   * @param timeout duration to wait before the peering attempt times out.
   * @return if connection is established
   */
  Status checkConnection(long timeout = -1);

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
  Status sendEvent(const std::string& topic, const broker::bro::Event& msg);

 private:
  // Mutex to synchronize threats that check connection state
  mutable Mutex connection_mutex_;
  // The IP and port of the remote endpoint
  std::pair<std::string, int> remote_endpoint_{"", 0};
  // The status_subscriber of the endpoint
  std::unique_ptr<broker::status_subscriber> ss_{nullptr};
  // The connection status
  broker::status connection_status_;

  // The ID identifying the node (private channel)
  std::string nodeID_;
  // The groups of the node
  std::vector<std::string> groups_;
  // The Broker Endpoint
  std::unique_ptr<broker::endpoint> ep_{nullptr};

  //  Key: topic_Name, Value: subscriber
  std::map<std::string, std::shared_ptr<broker::subscriber>> subscribers_;

  std::vector<std::string> startup_groups_;

 private:
  friend class BrokerManagerTests;
  FRIEND_TEST(BrokerManagerTests, test_failestablishconnection);
  FRIEND_TEST(BrokerManagerTests, test_successestablishconnection);
  FRIEND_TEST(BrokerManagerTests, test_announce);
  FRIEND_TEST(BrokerManagerTests, test_addandremovegroups);
  FRIEND_TEST(BrokerManagerTests, test_reconnect);
  FRIEND_TEST(BrokerManagerTests, test_reset);
};
} // namespace osquery
