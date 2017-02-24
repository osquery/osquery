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

void BroRunner::start() {
  // Setup Broker Endpoint
  LOG(INFO) << "Setup Broker Manager";
  broker::init();
  BrokerManager& bm = BrokerManager::getInstance();
  QueryManager& qm = QueryManager::getInstance();

  // Set Broker UID
  std::string ident;
  auto status_huuid = getHostUUID(ident);
  if (status_huuid.ok())
    bm.setNodeID(ident);
  const auto& uid = bm.getNodeID();

  // Subscribe to all and individual topic
  bm.createEndpoint(uid);
  bm.createMessageQueue(bm.TOPIC_ALL);
  bm.createMessageQueue(bm.TOPIC_PRE_INDIVIDUALS + uid);

  // Set Broker groups and subscribe to group topics
  std::vector<std::string> bro_groups;
  parseBrokerGroups(FLAGS_bro_groups, bro_groups);
  for (std::string g : bro_groups) {
    bm.addGroup(g);
  }

  // Connect to Bro and send announce message
  LOG(INFO) << "Connecting to '" << FLAGS_bro_ip << ":" << FLAGS_bro_port
            << "'";
  auto status_broker = bm.peerEndpoint(FLAGS_bro_ip, FLAGS_bro_port);
  if (!status_broker.ok()) {
    LOG(ERROR) << status_broker.getMessage();
    Initializer::requestShutdown(status_broker.getCode());
  }
  LOG(INFO) << "Broker connection established. "
            << "Ready to process, entering main loop.";

  /*
  *
  * MAIN Loop
  *
  */

  // Wait for any requests
  while (!interrupted()) {
    fd_set fds;
    std::vector<std::string> topics;
    int sock{0};
    std::shared_ptr<broker::message_queue> queue = nullptr;

    // Retrieve info about each message queue
    FD_ZERO(&fds);
    bm.getTopics(topics); // List of subscribed topics
    int sMax = 0;
    for (auto topic : topics) {
      sock = bm.getMessageQueue(topic)->fd();
      if (sock > sMax) {
        sMax = sock;
      }
      FD_SET(sock, &fds); // each topic -> message_queue -> fd
    }
    // Wait for incoming message
    if (select(sMax + 1, &fds, NULL, NULL, NULL) < 0) {
      LOG(ERROR) << "Select returned an error code";
      continue;
    }

    // Check for the socket where a message arrived on
    for (auto topic : topics) {
      queue = bm.getMessageQueue(topic);
      sock = queue->fd();
      if (FD_ISSET(sock, &fds)) {
        // Process each message on this socket
        for (auto& msg : queue->want_pop()) {
          // Check Event Type
          if (msg.size() < 1 or !broker::is<std::string>(msg[0])) {
            LOG(WARNING) << "No or invalid event name";
            continue;
          }
          std::string eventName = *broker::get<std::string>(msg[0]);
          LOG(INFO) << "Received event '" << eventName << "' on topic '"
                    << topic << "'";

          // osquery::host_execute
          if (eventName == bm.EVENT_HOST_EXECUTE) {
            // One-Time Query Execution
            SubscriptionRequest sr;
            createSubscriptionRequest("EXECUTE", msg, topic, sr);
            std::string newQID = qm.addOneTimeQueryEntry(sr);
            if (newQID == "-1") {
              LOG(ERROR) << "Unable to add Broker Query Entry";
              Initializer::requestShutdown(1);
            }

            // Execute the query
            LOG(INFO) << "Executing one-time query: " << sr.response_event
                      << ": " << sr.query;
            auto sql_query = SQL(sr.query);
            if (!sql_query.ok()) {
              LOG(ERROR) << "Executing one-time query failed";
              Initializer::requestShutdown();
            }

            QueryData results = sql_query.rows();
            if (results.empty()) {
              LOG(INFO) << "One-time query: " << sr.response_event
                        << " has no results";
              qm.removeQueryEntry(sr.query);
              continue;
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
            auto status_call =
                Registry::call(registry_name, item_name, request);
            if (!status_call.ok()) {
              std::string error =
                  "Error logging the results of one-time query: " + sr.query +
                  ": " + status_call.toString();
              LOG(ERROR) << error;
              Initializer::requestShutdown(EXIT_CATASTROPHIC, error);
            }

            continue;

            // osquery::host_join
          } else if (eventName == bm.EVENT_HOST_JOIN) {
            std::string newGroup = *broker::get<std::string>(msg[1]);
            bm.addGroup(newGroup);
            continue;

            // osquery::host_leave
          } else if (eventName == bm.EVENT_HOST_LEAVE) {
            std::string newGroup = *broker::get<std::string>(msg[1]);
            bm.removeGroup(newGroup);
            continue;

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
            LOG(ERROR) << "Unknown Event Name: '" << eventName << "'";
            LOG(ERROR) << "\t" << broker::to_string(msg);
            continue;
          }

          // Apply to new config/schedule
          std::map<std::string, std::string> config_schedule;
          config_schedule["bro"] = qm.getQueryConfigString();
          LOG(INFO) << "Applying new schedule: " << config_schedule["bro"];
          Config::getInstance().update(config_schedule);
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
