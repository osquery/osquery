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

BrokerManager* BrokerManager::_instance = nullptr;

BrokerManager::BrokerManager() {
  qm = QueryManager::getInstance();
}

Status BrokerManager::setNodeID(const std::string& uid) {
  if (nodeID.empty()) {
    // Save new node ID
    nodeID = uid;
    return Status(0, "OK");

  } else {
    LOG(WARNING) << "Node ID already set to '" << nodeID << "' (new: '"
                 << uid << "')";
    return Status(1, "Unable to set Node ID");
  }
}

std::string BrokerManager::getNodeID() {
  return nodeID;
}

Status BrokerManager::addGroup(const std::string& group) {
  groups.push_back(group);
  return createMessageQueue(TOPIC_PRE_GROUPS + group);
}

Status BrokerManager::removeGroup(const std::string& group) {
  auto element_pos = std::find(groups.begin(), groups.end(), group);
  // Group exists?
  if (element_pos != groups.end()) {
    // Delete Group
    groups.erase(element_pos);
    // Delete message queue (maybe)
    if (std::find(groups.begin(), groups.end(), group) ==
        groups.end()) {
      return deleteMessageQueue(TOPIC_PRE_GROUPS + group);
    } else {
      return Status(0, "More subscriptions for group exist");
    }
  }
  return Status(1, "Group does not exist");
}

std::vector<std::string> BrokerManager::getGroups() {
  return groups;
}

Status BrokerManager::createEndpoint(const std::string& ep_name) {
  if (ep != nullptr) {
    return Status(1, "Broker Endpoint already exists");
  }
  LOG(INFO) << "Creating broker endpoint with name: " << ep_name;
  ep = new broker::endpoint(ep_name);
  return Status(0, "OK");
}

broker::endpoint* BrokerManager::getEndpoint() {
  return ep;
}

Status BrokerManager::createMessageQueue(const std::string& topic) {
  if (messageQueues.count(topic) == 0) {
    LOG(INFO) << "Creating message queue: " << topic;
    broker::message_queue* mq = new broker::message_queue(topic, *(ep));
    messageQueues[topic] = mq;
    return Status(0, "OK");
  }
  return Status(1, "Message queue exists for topic");
}

Status BrokerManager::deleteMessageQueue(const std::string& topic) {
  if (messageQueues.count(topic) == 0) {
    return Status(1, "Message queue does not exist");
  }
  broker::message_queue* mq = messageQueues[topic];
  delete mq;
  messageQueues.erase(messageQueues.find(topic));
  return Status(0, "OK");
}

broker::message_queue* BrokerManager::getMessageQueue(
    const std::string& topic) {
  return messageQueues.at(topic);
}

Status BrokerManager::getTopics(std::vector<std::string>& topics) {
  topics.clear();
  for (const auto& mq : messageQueues) {
    topics.push_back(mq.first);
  }
  return Status(0, "OK");
}

Status BrokerManager::peerEndpoint(const std::string& ip, int port) {
  LOG(INFO) << "Connecting to " << ip << ":" << port;
  if (ep == nullptr) {
    return Status(1, "Broker Endpoint not set");
  }

  ep->peer(ip, port);
  auto cs = ep->outgoing_connection_status().need_pop().front();
  if (cs.status != broker::outgoing_connection_status::tag::established) {
    return Status(1, "Failed to connect to bro endpoint");
  }

  // Announce this endpoint to be a bro-osquery extension
  // Collect Groups
  broker::vector group_list;
  for (std::string g : getGroups()) {
    group_list.push_back(g);
  }
  // Collect IPs
  broker::vector addr_list;
  SQL sql("SELECT address from interface_addresses");
  if (sql.ok()) {
    for (const auto& row : sql.rows()) {
      std::string if_mac = row.at("address");
      addr_list.push_back(broker::data(broker::address::from_string(if_mac).get()));
    }
  } else {
    return Status(1, "Failed to retrieve interface addresses");
  }

  // Create Message
  broker::message announceMsg = broker::message{
          broker::data(EVENT_HOST_NEW), broker::data(getNodeID()), broker::data(group_list), broker::data(addr_list)};
  sendEvent(TOPIC_ANNOUNCE, announceMsg);

  return Status(0, "OK");
}

Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli) {
  const auto& queryID = qli.name;

  // Is this schedule or one-time? Get Query and Type
  std::string query = "";
  std::string qType = "";
  auto status_find = qm->findQueryAndType(queryID, qType, query);
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
  if (! status.ok()) {
    LOG(ERROR) << status.getMessage();
    Initializer::requestShutdown(status.getCode());
  }
  std::map<std::string, ColumnType> columnTypes;
  for (const auto& t : columns) {
    const auto& columnName = std::get<0>(t);
    const auto& columnType = std::get<1>(t);
    // ColumnOptions columnOptions = std::get<2>(t);
    columnTypes[columnName] = columnType;
    // LOG(INFO) << "Column named '" << columnName << "' is of type '" << kColumnTypeNames.at(columnType) << "'";
  }

  // Common message fields
  const auto& uid = getNodeID();
  const auto& topic = qm->getEventTopic(queryID);
  const auto& event_name = qm->getEventName(queryID);
  LOG(INFO) << "Creating " << rows.size() << " messages for events with name :'"
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
    broker::record result_info({broker::record::field(broker::data(uid)),
                                broker::record::field(broker::data(
                                    broker::enum_value{"osquery::" + trigger})),
                                broker::record::field(broker::data(
                                    qm->getEventCookie(queryID)))});
    msg.push_back(broker::data(result_info));

    // Format each column
    for (const auto& t : columns) {
      const auto& colName = std::get<0>(t);
      if (row.count(colName) != 1) {
        LOG(ERROR) << "Column '" << colName << "' not present in results for '"
                   << event_name << "'";
        for (const auto& pair : row) {
          LOG(ERROR) << "\t<" << pair.first << ", " << pair.second << "> ";
        }
        parse_err = true;
        break;
      }
      const auto& value = row.at(colName);
      switch (columnTypes.at(colName)) {
      case ColumnType::UNKNOWN_TYPE: {
        LOG(WARNING) << "Sending unknown column type as string";
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
        LOG(WARNING) << "Sending blob column type as string";
        msg.push_back(broker::data(value));
        break;
      }
      default: {
        LOG(WARNING) << "Unkown ColumnType!";
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
    qm->removeQueryEntry(query);
  }

  return Status(0, "OK");
}

Status BrokerManager::sendEvent(const std::string& topic,
                                const broker::message& msg) {
  if (ep == nullptr) {
    return Status(1, "Endpoint not set");
  } else {
    LOG(INFO) << "Sending Message: " << broker::to_string(msg) << " to " << topic;
    ep->send(topic, msg);
  }

  return Status(0, "OK");
}
}
