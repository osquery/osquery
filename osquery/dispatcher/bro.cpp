/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <unistd.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/bro/BrokerManager.h"
#include "osquery/bro/utils.h"
#include "osquery/dispatcher/bro.h"

namespace osquery {

FLAG(string, bro_ip, "localhost", "IP address of bro (default localhost)")

FLAG(uint64, bro_port, 9999, "Port of bro (default 9999)")

FLAG(string, bro_groups, "{}", "List of groups (default {})")

FLAG(bool, disable_bro, true, "Disable bro (default true)");

inline void processMessage(broker::message& msg,
                           BrokerManager& bm,
                           QueryManager& qm,
                           const std::string& topic) {
  // Check Event Type
  if (msg.size() < 1 or !broker::is<std::string>(msg[0])) {
    LOG(WARNING) << "No or invalid event name";
    return;
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
      LOG(ERROR) << "Unable to add Broker Query Entry";
      Initializer::requestShutdown(1);
    }

    // Execute the query
    LOG(INFO) << "Executing one-time query: " << sr.response_event << ": "
              << sr.query;
    auto sql_query = SQL(sr.query);
    if (!sql_query.ok()) {
      LOG(ERROR) << "Executing one-time query failed";
      Initializer::requestShutdown();
    }

    QueryData results = sql_query.rows();
    if (results.empty()) {
      VLOG(1) << "One-time query '" << sr.response_event << "' has no results";
      qm.removeQueryEntry(sr.query);
      return;
    }

    // Assemble a response item (as snapshot)
    QueryLogItem item;
    item.name = newQID;
    item.identifier = getHostIdentifier();
    item.time = getUnixTime();
    item.calendar_time = getAsciiTime();
    item.snapshot_results = results;

    // Send snapshot to the logger
    std::string registry_name = "logger";
    std::string item_name = "bro";
    std::string json;
    serializeQueryLogItemJSON(item, json);
    PluginRequest request = {{"snapshot", json}, {"category", "event"}};
    auto status_call = Registry::call(registry_name, item_name, request);
    if (!status_call.ok()) {
      LOG(ERROR) << status_call.getMessage();
      Initializer::requestShutdown(status_call.getCode());
    }
    return;

    // osquery::host_join
  } else if (eventName == bm.EVENT_HOST_JOIN) {
    std::string newGroup = *broker::get<std::string>(msg[1]);
    bm.addGroup(newGroup);
    return;

    // osquery::host_leave
  } else if (eventName == bm.EVENT_HOST_LEAVE) {
    std::string newGroup = *broker::get<std::string>(msg[1]);
    bm.removeGroup(newGroup);
    return;

    // osquery::host_subscribe
  } else if (eventName == bm.EVENT_HOST_SUBSCRIBE) {
    // New SQL Query Request
    SubscriptionRequest sr;
    createSubscriptionRequest("SUBSCRIBE", msg, topic, sr);
    qm.addScheduleQueryEntry(sr);

    // osquery::host_unsubscribe
  } else if (eventName == bm.EVENT_HOST_UNSUBSCRIBE) {
    // SQL Query Cancel
    SubscriptionRequest sr;
    createSubscriptionRequest("UNSUBSCRIBE", msg, topic, sr);
    // TODO: find an UNIQUE identifier (currently the exact sql string)
    std::string query = sr.query;

    qm.removeQueryEntry(query);

  } else if (eventName == "osquery::host_test") {
  } else {
    // Unkown Message
    LOG(ERROR) << "Unknown event name '" << eventName << "'";
    return;
  }

  // Apply to new config/schedule
  std::map<std::string, std::string> config_schedule;
  config_schedule["bro"] = qm.getQueryConfigString();
  VLOG(1) << "Applying new schedule: " << config_schedule["bro"];
  Config::get().update(config_schedule);
}

void BroRunner::start() {
  // Setup Broker Endpoint
  LOG(INFO) << "Starting the Bro Runner";
  broker::init();
  BrokerManager& bm = BrokerManager::get();
  QueryManager& qm = QueryManager::get();

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
  if (!status_broker.ok()) {
    LOG(ERROR) << status_broker.getMessage();
    Initializer::requestShutdown(status_broker.getCode());
  }
  VLOG(1) << "Broker connection established now entering main loop";

  /*
  *
  * MAIN Loop
  *
  */

  // Wait for any requests
  while (!interrupted()) {
    fd_set fds;
    std::vector<std::string> topics;

    // Retrieve info about each message queue
    FD_ZERO(&fds);
    bm.getTopics(topics); // List of subscribed topics
    int sMax = 0;
    for (const auto& topic : topics) {
      int sock = bm.getMessageQueue(topic)->fd();
      if (sock > sMax) {
        sMax = sock;
      }
      FD_SET(sock, &fds); // each topic -> message_queue -> fd
    }
    // Wait for incoming message
    int select_code = select(sMax + 1, &fds, nullptr, nullptr, nullptr);
    if (select_code < 0) {
      LOG(ERROR) << "Select returned the error code " << select_code;
      continue;
    }

    // Check for the socket where a message arrived on
    for (const auto& topic : topics) {
      std::shared_ptr<broker::message_queue> queue = bm.getMessageQueue(topic);
      if (FD_ISSET(queue->fd(), &fds)) {
        // Process each message on this socket
        for (auto& msg : queue->want_pop()) {
          processMessage(msg, bm, qm, topic);
        }
      }
    }
  }
}

Status startBro() {
  if (!FLAGS_disable_bro) {
    Dispatcher::addService(std::make_shared<BroRunner>());
    return Status(0, "OK");
  } else {
    return Status(1, "Bro query service not enabled.");
  }
}
}
