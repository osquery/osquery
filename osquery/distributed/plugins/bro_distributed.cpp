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

#include <sstream>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#include "osquery/remote/bro/bro_utils.h"
#include "osquery/remote/bro/broker_manager.h"
#include "osquery/remote/bro/query_manager.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string, bro_ip, "localhost", "IP address of bro (default localhost)")

FLAG(uint64, bro_port, 9999, "Port of bro (default 9999)")

FLAG(string, bro_groups, "{}", "List of groups (default {})")

/**
 * @brief Distributed Plugin for the communication with Bro via broker
 *
 * This DistributedPlugin is the main entry point for the communication with
 * Bro. It implements a server-"loop" to wait for any incoming messages via
 * broker. It utilizes the BrokerManager and QueryManager to keep state about
 * broker connections and query requests, respectively.
 *
 */
class BRODistributedPlugin : public DistributedPlugin {
 public:
  /**
   * @brief Setup of the plugin and preparation of the BrokerManager
   *
   * Initialization of the BrokerManager by connecting to the remote broker
   * endpoint, joining predefined groups and subscribing to predefined topics,
   * and announcing this osquery host.
   *
   * @return
   */
  Status setUp() override;

  /**
   * @brief Implementation of the main server-"loop" to process incoming
   * messages
   *
   * This base method was originally designed to retrieve the latest remote
   * configuration from server. However, the communication pattern with Bro is
   * not request-response-based but event-based. Thus, this method
   * implementation blocks until the next broker message is available to be
   * read. After return, this method is meant to be immediately be called again
   * to wait and process the next message.
   *
   * This method can be thought of the main-loop for receiving messages.
   * Incoming messages are parsed and the respective functions are called. There
   * are mainly three actions available:
   *   1) Schedule Subscription: registers a new query that is pushed to the
   * osqueryd daemon for query schedule
   *   2) Schedule Unsibscription: unregister a previously subscribed schedule
   * query and remove it from osquery daemon
   *   3) One-Time Execution: make the parent execute an one-time query
   *
   * @param json the one-time queries to be executed by the "parent"
   * @return
   */
  Status getQueries(std::string& json) override;

  /**
   * @brief Write the results of the one-time queries via the bro logger plugin
   *
   * @param json the results of the one-time queries
   * @return
   */
  Status writeResults(const std::string& json) override;

 private:
  std::vector<std::string> startup_groups_;
};

REGISTER(BRODistributedPlugin, "distributed", "bro");

Status BRODistributedPlugin::setUp() {
  // Setup Broker Endpoint
  LOG(INFO) << "Starting the Bro Distributed Plugin";
  broker::init();
  BrokerManager& bm = BrokerManager::get();

  // Subscribe to all and individual topic
  auto s = bm.createMessageQueue(bm.TOPIC_ALL);
  if (!s.ok()) {
    return s;
  }
  s = bm.createMessageQueue(bm.TOPIC_PRE_INDIVIDUALS + bm.getNodeID());
  if (!s.ok()) {
    return s;
  }

  // Set Broker groups and subscribe to group topics
  s = parseBrokerGroups(FLAGS_bro_groups, startup_groups_);
  if (!s.ok()) {
    return s;
  }
  for (const auto& g : startup_groups_) {
    bm.addGroup(g);
  }

  // Connect to Bro
  s = bm.peerEndpoint(FLAGS_bro_ip, FLAGS_bro_port);
  if (!s.ok()) {
    return s;
  }
  VLOG(1) << "Broker connection established";

  // Send announce message
  s = bm.announce();
  if (!s.ok()) {
    return s;
  }

  return Status(0, "OK");
}

/**
 * @brief process a broker message that was received on the main-server-loop
 *
 * The messages actions depends on its message type.
 *
 *  EVENT_HOST_JOIN: Makes the osquery host to join a group (subscribe to broker
 * topic) utilizing BrokerManager
 *  EVENT_HOST_LEAVE: Makes the osquery host to leave a group (unsubscribe from
 * broker topic) utilizing BrokerManager
 *  EVENT_HOST_EXECUTE: add the query to the vector oT_queries and keep track
 * utilizing QueryManager
 *  EVENT_HOST_SUBSCRIBE: add the query to schedule of osquery daemon utilizing
 * the QueryManager
 *  EVENT_HOST_UNSUBSCRIBE: remove the query from schedule of osquery daemon
 * utilizing the QueryManager
 *
 * @param msg the broker message
 * @param topic the topic where the broker message was received on
 * @param oT_queries a vector to append one-time queries to
 * @return
 */
inline Status processMessage(const broker::message& msg,
                             const std::string& topic,
                             std::vector<DistributedQueryRequest>& oT_queries) {
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();
  Status s;

  // Check Event Type
  if (msg.size() < 1 || !broker::is<std::string>(msg[0])) {
    return Status(1, "No or invalid event name when processing message");
  }
  std::string eventName = *broker::get<std::string>(msg[0]);
  LOG(INFO) << "Received event '" << eventName << "' on topic '" << topic
            << "'";

  // osquery::host_execute
  if (eventName == bm.EVENT_HOST_EXECUTE) {
    // One-Time Query Execution
    SubscriptionRequest sr;
    createSubscriptionRequest(EXECUTE, msg, topic, sr);
    std::string newQID = qm.addOneTimeQueryEntry(sr);
    if (newQID.empty()) {
      return Status(1, "Unable to add Broker Query Entry");
    }
    DistributedQueryRequest dqr;
    dqr.id = newQID;
    dqr.query = sr.query;
    oT_queries.push_back(dqr);
    return Status(0, "OK");

    // osquery::host_join
  } else if (eventName == bm.EVENT_HOST_JOIN) {
    std::string newGroup = *broker::get<std::string>(msg[1]);
    return bm.addGroup(newGroup);

    // osquery::host_leave
  } else if (eventName == bm.EVENT_HOST_LEAVE) {
    std::string newGroup = *broker::get<std::string>(msg[1]);
    return bm.removeGroup(newGroup);

    // osquery::host_subscribe
  } else if (eventName == bm.EVENT_HOST_SUBSCRIBE) {
    // New SQL Query Request
    SubscriptionRequest sr;
    createSubscriptionRequest(SUBSCRIBE, msg, topic, sr);
    s = qm.addScheduleQueryEntry(sr);
    if (!s.ok()) {
      return s;
    }

    // osquery::host_unsubscribe
  } else if (eventName == bm.EVENT_HOST_UNSUBSCRIBE) {
    // SQL Query Cancel
    SubscriptionRequest sr;
    createSubscriptionRequest(UNSUBSCRIBE, msg, topic, sr);
    std::string query = sr.query;

    // Use the exact sql string as UNIQUE identifier for identifying a query
    s = qm.removeQueryEntry(query);
    if (!s.ok()) {
      return s;
    }

  } else {
    // Unkown Message
    return Status(1, "Unknown event name '" + eventName + "'");
  }

  // Apply to new config/schedule
  std::map<std::string, std::string> config_schedule;
  config_schedule["bro"] = qm.getQueryConfigString();
  VLOG(1) << "Applying new schedule by bro_distributed";
  Config::get().update(config_schedule);

  return Status(0, "OK");
}

Status BRODistributedPlugin::getQueries(std::string& json) {
  BrokerManager& bm = BrokerManager::get();
  Status s;

  // Collect file descriptors of the broker message queues
  std::vector<std::string> topics = bm.getTopics();
  // Retrieve info about each message queue and the file descriptor
  std::unique_ptr<pollfd[]> fds(new pollfd[topics.size() + 1]);
  for (unsigned long i = 0; i < topics.size(); i++) {
    fds[i] =
        pollfd{bm.getMessageQueue(topics.at(i))->fd(), POLLIN | POLLERR, 0};
  }
  // Append the connection status file descriptor to detect connection failures
  fds[topics.size()] =
      pollfd{bm.getOutgoingConnectionFD(), POLLIN | POLLERR, 0};
  assert(bm.getOutgoingConnectionFD() > 0);

  // Wait for incoming message
  poll(fds.get(), topics.size() + 1, -1);

  // Collect OneTime Queries
  std::vector<DistributedQueryRequest> oT_queries;

  // Check for the socket where a message arrived on
  for (unsigned long i = 0; i < topics.size(); i++) {
    if (fds[i].revents == 0) {
      // Nothing to do for this socket
      continue;
    }
    const auto& topic = topics.at(i);

    if ((fds[i].revents & POLLERR) == POLLERR) {
      // Error on this socket
      LOG(WARNING) << "Poll error on fd of queue for topic '" << topic << "'";
      continue;
    }

    std::shared_ptr<broker::message_queue> queue = bm.getMessageQueue(topic);
    // Process each message on this socket
    for (const auto& msg : queue->want_pop()) {
      // Directly updates the daemon schedule if requested
      // Returns one time queries otherwise
      s = processMessage(msg, topic, oT_queries);
      if (!s.ok()) {
        LOG(ERROR) << s.getMessage();
        continue;
      }
    }
  }

  // Serialize the distributed query requests
  pt::ptree request_queries;
  for (const auto& ot_query : oT_queries) {
    VLOG(1) << "Received DistributedQueryRequest for one-time query '"
            << ot_query.query << "' (ID: " << ot_query.id << ")";
    request_queries.put<std::string>(ot_query.id, ot_query.query);
  }
  pt::ptree request;
  request.add_child("queries", request_queries);

  pt::ptree params;
  s = JSONSerializer{}.serialize(request, json);
  if (!s.ok()) {
    LOG(ERROR) << s.getMessage();
    return s;
  }

  // Check for connection failure - wait until connection is repaired
  if ((fds[topics.size()].revents & POLLERR) == POLLERR) {
    LOG(ERROR) << "Poll error on the broker connection fd";
  }

  if (fds[topics.size()].revents != 0) {
    LOG(WARNING) << "Broker connection disconnected";
    // Connection was/is lost - Retrieve the latest connection status
    broker::outgoing_connection_status::tag conn_status;
    s = bm.getOutgoingConnectionStatusChange(conn_status, true);

    // Reset config/schedule
    std::map<std::string, std::string> config_schedule;
    config_schedule["bro"] = "";
    VLOG(1) << "Reset config schedule";
    Config::get().update(config_schedule);

    QueryManager::get().reset();
    BrokerManager::get().reset();

    // Set Startup groups and subscribe to group topics
    for (const auto& g : startup_groups_) {
      bm.addGroup(g);
    }

    // Wait for connection to be re-established
    while (!s.ok() &&
           conn_status !=
               broker::outgoing_connection_status::tag::established) {
      LOG(WARNING) << "Trying to re-establish broker connection";
      s = bm.getOutgoingConnectionStatusChange(conn_status, true);
    }

    // Send announce message
    s = bm.announce();
    if (!s.ok()) {
      LOG(ERROR) << s.getMessage();
      return s;
    }
  }

  return Status(0, "OK");
}

Status BRODistributedPlugin::writeResults(const std::string& json) {
  QueryManager& qm = QueryManager::get();

  JSON doc;
  if (!doc.fromString(json)) {
    return Status(1, "Cannot deserialize JSON");
  }

  if (!doc.doc().HasMember("queries") || !doc.doc()["queries"].IsObject()) {
    return Status(1, "Cannot find queries object");
  }

  // For each query
  for (const auto& query : doc.doc()["queries"].GetObject()) {
    // Get the query ID
    std::string queryID = query.name.GetString();
    VLOG(1) << "Writing results for onetime query with ID '" << queryID << "'";

    // Get the query data
    QueryData results;
    deserializeQueryData(query.value, results);

    // Get Query Info from QueryManager
    std::string response_event = qm.getEventName(queryID);
    std::string queryName, qType;
    qm.findQueryAndType(queryID, qType, queryName);

    // Any results for this query?
    if (results.empty()) {
      VLOG(1) << "One-time query '" << response_event << "' has no results";
      qm.removeQueryEntry(queryName);
      return Status(0, "OK");
    }

    // Assemble a response item (as snapshot)
    QueryLogItem item;
    item.name = queryID;
    item.identifier = getHostIdentifier();
    item.time = getUnixTime();
    item.calendar_time = getAsciiTime();
    item.snapshot_results = results;

    // Send snapshot to the logger
    std::string registry_name = "logger";
    std::string item_name = "bro";
    std::string json_str;
    serializeQueryLogItemJSON(item, json_str);
    PluginRequest request = {{"snapshot", json_str}, {"category", "event"}};
    auto s = Registry::call(registry_name, item_name, request);
    if (!s.ok()) {
      return s;
    }
  }

  return Status(0, "OK");
}
} // namespace osquery
