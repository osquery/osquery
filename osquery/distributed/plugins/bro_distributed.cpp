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

#include "osquery/remote/bro/broker_manager.h"
#include "osquery/remote/bro/query_manager.h"
#include "osquery/remote/bro/bro_utils.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string, bro_ip, "localhost", "IP address of bro (default localhost)")

FLAG(uint64, bro_port, 9999, "Port of bro (default 9999)")

FLAG(string, bro_groups, "{}", "List of groups (default {})")

class BRODistributedPlugin : public DistributedPlugin {
 public:
  Status setUp() override;

  Status getQueries(std::string& json) override;

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

inline Status processMessage(const broker::message& msg,
                             const std::string& topic,
                             std::vector<DistributedQueryRequest>& oT_queries) {
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();

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
    createSubscriptionRequest("EXECUTE", msg, topic, sr);
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
    createSubscriptionRequest("SUBSCRIBE", msg, topic, sr);
    Status s_sub = qm.addScheduleQueryEntry(sr);
    if (!s_sub.ok()) {
      return s_sub;
    }

    // osquery::host_unsubscribe
  } else if (eventName == bm.EVENT_HOST_UNSUBSCRIBE) {
    // SQL Query Cancel
    SubscriptionRequest sr;
    createSubscriptionRequest("UNSUBSCRIBE", msg, topic, sr);
    // TODO: find an UNIQUE identifier (currently the exact sql string)
    std::string query = sr.query;

    Status s_unsub = qm.removeQueryEntry(query);
    if (!s_unsub.ok()) {
      return s_unsub;
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
  std::vector<std::string> topics = bm.getTopics(); // List of subscribed topics
  // Retrieve info about each message queue
  // TODO is this smart pointer? Should be safe for unique_ptr
  // https://stackoverflow.com/questions/6713484/smart-pointers-and-arrays
  // https://stackoverflow.com/questions/13061979/shared-ptr-to-an-array-should-it-be-used
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
  // TODO is this allowed?
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
      LOG(ERROR) << "Poll error on fd of queue for topic '" << topic << "'";
      continue;
    }

    // fds[i].revents == POLLIN
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
    VLOG(1) << "Received DistributedQueryRequest '" << ot_query.query
            << "' (ID: " << ot_query.id << ")";
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
      LOG(WARNING) << "Trying to re-establish broker connection...";
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

  // Put query results into a pt
  pt::ptree params;
  Status s = JSONSerializer{}.deserialize(json, params);
  if (!s.ok()) {
    return s;
  }

  // For each query
  for (const auto& query_params : params.get_child("queries")) {
    // Get the query ID
    std::string queryID = query_params.first;
    VLOG(1) << "Writing results for onetime query with ID '" << queryID << "'";

    // Get the query data
    QueryData results;
    deserializeQueryData(query_params.second, results);

    // Get Query Info from QueryManager
    std::string response_event = qm.getEventName(queryID);
    std::string query, qType;
    qm.findQueryAndType(queryID, qType, query);

    // Any results for this query?
    if (results.empty()) {
      VLOG(1) << "One-time query '" << response_event << "' has no results";
      qm.removeQueryEntry(query);
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
    s = Registry::call(registry_name, item_name, request);
    if (!s.ok()) {
      return s;
    }
  }

  return Status(0, "OK");
}
}
