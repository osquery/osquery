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

#include <broker/bro.hh>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#include "osquery/remote/bro/bro_utils.h"
#include "osquery/remote/bro/broker_manager.h"
#include "osquery/remote/bro/query_manager.h"

namespace pt = boost::property_tree;

namespace osquery {

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
};

REGISTER(BRODistributedPlugin, "distributed", "bro");

Status BRODistributedPlugin::setUp() {
  LOG(INFO) << "Starting the Bro Distributed Plugin";

  // Initiate Peering
  BrokerManager::get().checkConnection(0);

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
 * @param event the broker message
 * @param topic the topic where the broker message was received on
 * @param oT_queries a vector to append one-time queries to
 * @return
 */
inline Status processMessage(const broker::bro::Event& event,
                             const std::string& topic,
                             std::vector<DistributedQueryRequest>& oT_queries) {
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();
  Status s;
  auto event_args = event.args();

  // Check Event Type
  if (event.name().empty()) {
    return Status(1,
                  "No or invalid event name '" + event.name() +
                      "'when processing message");
  }
  LOG(INFO) << "Received event '" << event.name() << "' on topic '" << topic
            << "'";

  // osquery::host_execute
  if (event.name() == bm.EVENT_HOST_EXECUTE) {
    // One-Time Query Execution
    SubscriptionRequest sr;
    createSubscriptionRequest(EXECUTE, event, topic, sr);
    std::string newQID = qm.addOneTimeQueryEntry(sr);
    if (newQID.empty()) {
      return Status(1, "Unable to add Broker Query Entry");
    }
    DistributedQueryRequest dqr;
    dqr.id = newQID;
    dqr.query = sr.query;
    oT_queries.push_back(dqr);
    return Status(0, "OK");

    // osquery::host_subscribe
  } else if (event.name() == bm.EVENT_HOST_SUBSCRIBE) {
    // New SQL Query Request
    SubscriptionRequest sr;
    createSubscriptionRequest(SUBSCRIBE, event, topic, sr);
    s = qm.addScheduleQueryEntry(sr);
    if (!s.ok()) {
      return s;
    }

    // osquery::host_unsubscribe
  } else if (event.name() == bm.EVENT_HOST_UNSUBSCRIBE) {
    // SQL Query Cancel
    SubscriptionRequest sr;
    createSubscriptionRequest(UNSUBSCRIBE, event, topic, sr);
    std::string query = sr.query;

    // Use the exact sql string as UNIQUE identifier for identifying a query
    s = qm.removeQueryEntry(query);
    if (!s.ok()) {
      return s;
    }

    // osquery::host_join
  } else if (event.name() == bm.EVENT_HOST_JOIN) {
    if (event_args.size() != 1) {
      return Status(1, "Unable to parse message '" + event.name() + "'");
    }
    if (auto newGroup = broker::get_if<std::string>(event_args[0])) {
      return bm.addGroup(*newGroup);
    }
    return Status(1, "Unable to parse message '" + event.name() + "'");

    // osquery::host_leave
  } else if (event.name() == bm.EVENT_HOST_LEAVE) {
    if (event_args.size() != 1) {
      return Status(1, "Unable to parse message '" + event.name() + "'");
    }
    if (auto newGroup = broker::get_if<std::string>(event_args[0])) {
      return bm.removeGroup(*newGroup);
    }
    return Status(1, "Unable to parse message '" + event.name() + "'");

  } else {
    // Unkown Message
    return Status(1, "Unknown event name '" + event.name() + "'");
  }

  // Apply to new config/schedule
  qm.updateSchedule();

  return Status(0, "OK");
}

Status BRODistributedPlugin::getQueries(std::string& json) {
  BrokerManager& bm = BrokerManager::get();
  Status s;

  // Check for connection failure and wait for repair
  s = bm.checkConnection();
  if (!s.ok()) {
    LOG(WARNING) << "Unable to repair broker connection";
    return s;
  }

  // Collect all topics and subscribers
  std::vector<std::string> topics = bm.getTopics();
  // Retrieve info about each subscriber and the file descriptor
  std::unique_ptr<pollfd[]> fds(new pollfd[topics.size() + 1]);
  for (unsigned long i = 0; i < topics.size(); i++) {
    fds[i] = pollfd{bm.getSubscriber(topics.at(i))->fd(), POLLIN | POLLERR, 0};
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
    // Pick topic of the respective socket
    const auto& topic = topics.at(i);

    if ((fds[i].revents & POLLERR) == POLLERR) {
      // Error on this socket
      LOG(WARNING) << "Poll error on fd of queue for topic '" << topic << "'";
      continue;
    }

    std::shared_ptr<broker::subscriber> sub = bm.getSubscriber(topic);
    // Process each message on this socket
    for (const auto& msg : sub->poll()) {
      // Directly updates the daemon schedule if requested
      // Returns one time queries otherwise
      assert(topic == msg.first);
      broker::bro::Event event(msg.second);
      VLOG(1) << "Processing received event: "
              << broker::to_string(event.as_data());
      s = processMessage(event, topic, oT_queries);

      if (!s.ok()) {
        LOG(ERROR) << s.getMessage();
        continue;
      }
    }
  }

  // Check the broker connection
  if (fds[topics.size()].revents == 1) {
    VLOG(1) << "Break fd loop because broker connection changed";
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
