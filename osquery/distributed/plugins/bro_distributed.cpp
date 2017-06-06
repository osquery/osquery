/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// clang-format off
// This must be here to prevent a WinSock.h exists error
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <vector>
#include <sstream>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/distributed.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#include "osquery/remote/bro/BrokerManager.h"
#include "osquery/remote/bro/QueryManager.h"
#include "osquery/remote/bro/utils.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string, bro_ip, "localhost", "IP address of bro (default localhost)")

FLAG(uint64, bro_port, 9999, "Port of bro (default 9999)")

FLAG(string, bro_groups, "{}", "List of groups (default {})")

FLAG(bool, disable_bro, true, "Disable bro (default true)");

class BRODistributedPlugin : public DistributedPlugin {
 public:
  Status setUp() override;

  Status getQueries(std::string& json) override;

  Status writeResults(const std::string& json) override;

 protected:
  std::string read_uri_;
  std::string write_uri_;
};

REGISTER(BRODistributedPlugin, "distributed", "bro");

Status BRODistributedPlugin::setUp() {
  // Setup Broker Endpoint
  LOG(INFO) << "Starting the Bro Distributed Plugin";
  broker::init();
  BrokerManager& bm = BrokerManager::get();

  // Set Broker UID
  std::string ident;
  auto status_huuid = getHostUUID(ident);
  if (status_huuid.ok()) {
    bm.setNodeID(ident);
  }
  const auto& uid = bm.getNodeID();

  // Subscribe to all and individual topic
  bm.createEndpoint(uid);
  bm.createMessageQueue(bm.TOPIC_ALL);
  bm.createMessageQueue(bm.TOPIC_PRE_INDIVIDUALS + uid);

  // Set Broker groups and subscribe to group topics
  std::vector<std::string> bro_groups;
  parseBrokerGroups(FLAGS_bro_groups, bro_groups);
  for (const auto& g : bro_groups) {
    bm.addGroup(g);
  }

  // Connect to Bro and send announce message
  auto status_broker = bm.peerEndpoint(FLAGS_bro_ip, FLAGS_bro_port);
  if (status_broker.ok()) {
    VLOG(1) << "Broker connection established";
  }

  return status_broker;
}

inline Status processMessage(const broker::message& msg,
                             const std::string& topic,
                             std::vector<DistributedQueryRequest> oT_queries) {
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();

  // Check Event Type
  if (msg.size() < 1 or !broker::is<std::string>(msg[0])) {
    return Status(3, "No or invalid event name when processing message");
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
      return Status(8, "Unable to add Broker Query Entry");
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

  } else if (eventName == "osquery::host_test") {
  } else {
    // Unkown Message
    return Status(7, "Unknown event name '" + eventName + "'");
  }

  // Apply to new config/schedule
  std::map<std::string, std::string> config_schedule;
  config_schedule["bro"] = qm.getQueryConfigString();
  VLOG(1) << "Applying new schedule: " << config_schedule["bro"];
  Config::get().update(config_schedule);

  return Status(0, "OK");
}

Status BRODistributedPlugin::getQueries(std::string& json) {
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();

  // Collect file descriptors of the broker message queues
  // TODO: Include the outgoing_message_queue to detect connection failures
  fd_set fds;
  FD_ZERO(&fds);
  std::vector<std::string> topics = bm.getTopics(); // List of subscribed topics
  int sMax = 0;
  // Retrieve info about each message queue
  for (const auto& topic : topics) {
    int sock = bm.getMessageQueue(topic)->fd();
    if (sock > sMax) {
      sMax = sock;
    }
    FD_SET(sock, &fds); // each topic -> message_queue -> fd
  }
  // Wait for incoming message
  int select_code = select(sMax + 1, &fds, nullptr, nullptr, nullptr);
  // Select interrupted for another reason than incoming message or timeout
  if (select_code < 0) {
    return Status(
        5, "Select returned the error code: " + std::to_string(select_code));
  }

  // Collect OneTime Queries
  std::vector<DistributedQueryRequest> oT_queries;

  // Check for the socket where a message arrived on
  for (const auto& topic : topics) {
    std::shared_ptr<broker::message_queue> queue = bm.getMessageQueue(topic);
    if (FD_ISSET(queue->fd(), &fds)) {
      // Process each message on this socket
      for (const auto& msg : queue->want_pop()) {
        // Directly updates the daemon schedule if requested
        // Returns one time queries otherwise
        Status s_msg = processMessage(msg, topic, oT_queries);
        if (!s_msg.ok()) {
          return s_msg;
        }
      }
    }
  }

  // Serialize the distributed query requests
  pt::ptree request_queries;
  for (const auto& ot_query : oT_queries) {
    request_queries.put<std::string>(ot_query.id, ot_query.query);
  }
  pt::ptree request;
  request.add_child("queries", request_queries);

  return Status(0, "OK");
}

Status BRODistributedPlugin::writeResults(const std::string& json) {
  QueryManager& qm = QueryManager::get();

  // Put query results into a pt
  pt::ptree params;
  Status s_deserial = JSONSerializer{}.deserialize(json, params);
  if (!s_deserial.ok()) {
    return s_deserial;
  }

  // For each query
  for (const auto& query_params : params.get_child("queries")) {
    // Get the query ID
    std::string queryID = query_params.first;
    VLOG(1) << "Writing results for query with ID '" << queryID << "'";

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

    // TODO: when is the query removed from the QueryManager?

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
    auto status_call = Registry::call(registry_name, item_name, request);
    if (!status_call.ok()) {
      return status_call;
    }
  }

  return Status(0, "OK");
}
}
