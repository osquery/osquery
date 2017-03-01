/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/bro/BrokerManager.h"
#include "osquery/bro/utils.h"

namespace osquery {

Status BrokerManager::setNodeID(const std::string& uid) {
  if (!nodeID_.empty()) {
    return Status(
        1, "Node ID already set to '" + nodeID_ + "' (new: '" + uid + "')");
  }

  // Save new node ID
  nodeID_ = uid;
  return Status(0, "OK");
}

std::string BrokerManager::getNodeID() {
  return nodeID_;
}

Status BrokerManager::addGroup(const std::string& group) {
  groups_.push_back(group);
  return createMessageQueue(TOPIC_PRE_GROUPS + group);
}

Status BrokerManager::removeGroup(const std::string& group) {
  auto element_pos = std::find(groups_.begin(), groups_.end(), group);
  // Group exists?
  if (element_pos == groups_.end()) {
    return Status(1, "Group '" + group + "' does not exist");
  }

  // Delete Group
  groups_.erase(element_pos);
  // Delete message queue (maybe)
  if (std::find(groups_.begin(), groups_.end(), group) != groups_.end()) {
    return Status(0, "More subscriptions for group '" + group + "' exist");
  }

  return deleteMessageQueue(TOPIC_PRE_GROUPS + group);
}

std::vector<std::string> BrokerManager::getGroups() {
  return groups_;
}

Status BrokerManager::createEndpoint(const std::string& ep_name) {
  if (ep_ != nullptr) {
    return Status(1, "Broker Endpoint already exists");
  }

  VLOG(1) << "Creating broker endpoint with name: " << ep_name;
  ep_ = std::make_unique<broker::endpoint>(ep_name);
  return Status(0, "OK");
}

Status BrokerManager::createMessageQueue(const std::string& topic) {
  if (messageQueues_.count(topic) != 0) {
    return Status(1, "Message queue exists for topic '" + topic + "'");
  }

  VLOG(1) << "Creating message queue: " << topic;
  messageQueues_[topic] =
      std::make_shared<broker::message_queue>(topic, *(ep_));
  return Status(0, "OK");
}

Status BrokerManager::deleteMessageQueue(const std::string& topic) {
  if (messageQueues_.count(topic) == 0) {
    return Status(1, "Message queue does not exist for topic '" + topic + "'");
  }

  // shared_ptr should delete the message_queue and unsubscribe from topic
  messageQueues_.erase(messageQueues_.find(topic));
  return Status(0, "OK");
}

std::shared_ptr<broker::message_queue> BrokerManager::getMessageQueue(
    const std::string& topic) {
  return messageQueues_.at(topic);
}

Status BrokerManager::getTopics(std::vector<std::string>& topics) {
  topics.clear();
  for (const auto& mq : messageQueues_) {
    topics.push_back(mq.first);
  }
  return Status(0, "OK");
}

Status BrokerManager::peerEndpoint(const std::string& ip, int port) {
  LOG(INFO) << "Connecting to Bro " << ip << ":" << port;
  if (ep_ == nullptr) {
    return Status(1, "Broker Endpoint not set");
  }

  ep_->peer(ip, port);
  auto cs = ep_->outgoing_connection_status().need_pop().front();
  if (cs.status != broker::outgoing_connection_status::tag::established) {
    return Status(1, "Failed to connect to bro endpoint");
  }

  // Announce this endpoint to be a bro-osquery extension
  // Collect Groups
  broker::vector group_list;
  for (const auto& g : getGroups()) {
    group_list.push_back(g);
  }
  // Collect IPs
  broker::vector addr_list;
  SQL sql("SELECT address from interface_addresses");
  if (!sql.ok()) {
    return Status(1, "Failed to retrieve interface addresses");
  }
  for (const auto& row : sql.rows()) {
    const auto& if_mac = row.at("address");
    addr_list.push_back(
        broker::data(broker::address::from_string(if_mac).get()));
  }

  // Create Message
  broker::message announceMsg = broker::message{broker::data(EVENT_HOST_NEW),
                                                broker::data(getNodeID()),
                                                broker::data(group_list),
                                                broker::data(addr_list)};
  sendEvent(TOPIC_ANNOUNCE, announceMsg);

  return Status(0, "OK");
}

Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli) {
  const auto& queryID = qli.name;

  // Is this schedule or one-time? Get Query and Type
  std::string query = "";
  std::string qType = "";
  auto status_find =
      QueryManager::getInstance().findQueryAndType(queryID, qType, query);
  if (!status_find.ok()) {
    return status_find;
  }

  // Rows to be reported
  std::vector<std::tuple<Row, std::string>> rows;
  for (const auto& row : qli.results.added) {
    rows.emplace_back(row, "ADD");
  }
  for (const auto& row : qli.results.removed) {
    rows.emplace_back(row, "REMOVE");
  }
  for (const auto& row : qli.snapshot_results) {
    rows.emplace_back(row, "SNAPSHOT");
  }

  // Get Info about SQL Query and Types
  TableColumns columns;
  auto status = getQueryColumns(query, columns);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    Initializer::requestShutdown(status.getCode());
  }
  std::map<std::string, ColumnType> columnTypes;
  for (const auto& t : columns) {
    const auto& columnName = std::get<0>(t);
    const auto& columnType = std::get<1>(t);
    columnTypes[columnName] = columnType;
  }

  // Common message fields
  const auto& uid = getNodeID();
  const auto& topic = QueryManager::getInstance().getEventTopic(queryID);
  const auto& event_name = QueryManager::getInstance().getEventName(queryID);
  VLOG(1) << "Creating " << rows.size() << " messages with event name '"
          << event_name << "'";

  // Create message for each row
  bool parse_err = false;
  for (const auto& element : rows) {
    // Get row and trigger
    const auto& row = std::get<0>(element);
    const auto& trigger = std::get<1>(element);

    // Set event name, uid and trigger
    broker::message msg;
    msg.push_back(event_name);
    broker::record result_info(
        {broker::record::field(broker::data(uid)),
         broker::record::field(
             broker::data(broker::enum_value{"osquery::" + trigger})),
         broker::record::field(broker::data(
             QueryManager::getInstance().getEventCookie(queryID)))});
    msg.push_back(broker::data(result_info));

    // Format each column
    for (const auto& t : columns) {
      const auto& colName = std::get<0>(t);
      if (row.count(colName) != 1) {
        LOG(ERROR) << "Column '" << colName << "' not present in results for '"
                   << event_name << "'";
        parse_err = true;
        break;
      }
      const auto& value = row.at(colName);
      switch (columnTypes.at(colName)) {
      case ColumnType::UNKNOWN_TYPE: {
        LOG(WARNING) << "Sending unknown column type for column '" + colName +
                            "' as string";
        msg.push_back(broker::data(value));
        break;
      }
      case ColumnType::TEXT_TYPE: {
        msg.push_back(broker::data(AS_LITERAL(TEXT_LITERAL, value)));
        break;
      }
      case ColumnType::INTEGER_TYPE: {
        msg.push_back(broker::data(AS_LITERAL(INTEGER_LITERAL, value)));
        break;
      }
      case ColumnType::BIGINT_TYPE: {
        msg.push_back(broker::data(AS_LITERAL(BIGINT_LITERAL, value)));
        break;
      }
      case ColumnType::UNSIGNED_BIGINT_TYPE: {
        msg.push_back(broker::data(AS_LITERAL(UNSIGNED_BIGINT_LITERAL, value)));
        break;
      }
      case ColumnType::DOUBLE_TYPE: {
        msg.push_back(broker::data(AS_LITERAL(DOUBLE_LITERAL, value)));
        break;
      }
      case ColumnType::BLOB_TYPE: {
        LOG(WARNING) << "Sending blob column type for column '" + colName +
                            "' as string";
        msg.push_back(broker::data(value));
        break;
      }
      default: {
        LOG(WARNING) << "Unknown ColumnType for column '" + colName + "'";
        continue;
      }
      }
    }

    // Send event message
    sendEvent(topic, msg);
  }

  if (parse_err) {
    printQueryLogItem(qli);
  }

  // Delete one-time query information
  if (qType == "ONETIME") {
    QueryManager::getInstance().removeQueryEntry(query);
  }

  return Status(0, "OK");
}

Status BrokerManager::sendEvent(const std::string& topic,
                                const broker::message& msg) {
  if (ep_ == nullptr) {
    return Status(1, "Endpoint not set");
  } else {
    VLOG(1) << "Sending Message '" << broker::to_string(msg) << "' to  topic '"
            << topic << "'";
    ep_->send(topic, msg);
  }

  return Status(0, "OK");
}
}
