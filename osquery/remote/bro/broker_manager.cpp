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

#include <boost/lexical_cast.hpp>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/remote/bro/bro_utils.h"
#include "osquery/remote/bro/broker_manager.h"

namespace osquery {

Status BrokerManager::reset(bool groups_only) {
  // Unsubscribe from all groups
  std::vector<std::string> cp_groups(groups_);
  for (const auto& g : cp_groups) {
    Status s = removeGroup(g);
    if (not s.ok()) {
      return s;
    }
  }

  if (groups_only) {
    return Status(0, "OK");
  }

  // Remove all remaining message queues (manually added)
  std::map<std::string, std::shared_ptr<broker::message_queue>> cp_queues(
      messageQueues_);
  for (const auto& q : cp_queues) {
    Status s = deleteMessageQueue(q.first);
    if (not s.ok()) {
      return s;
    }
  }

  return Status(0, "OK");
}

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
  Status s = createMessageQueue(TOPIC_PRE_GROUPS + group);
  if (not s.ok()) {
    return s;
  }
  groups_.push_back(group);
  return Status(0, "OK");
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
  if (ep_ == nullptr) {
    return Status(1, "Broker Endpoint does not exist");
  }

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

std::vector<std::string> BrokerManager::getTopics() {
  std::vector<std::string> topics;
  for (const auto& mq : messageQueues_) {
    topics.push_back(mq.first);
  }
  return topics;
}

Status BrokerManager::peerEndpoint(const std::string& ip,
                                   int port,
                                   int timeout) {
  LOG(INFO) << "Connecting to Bro " << ip << ":" << port;
  if (ep_ == nullptr) {
    return Status(1, "Broker Endpoint not set");
  }

  if (p_ != nullptr) {
    return Status(1, "Broker conenction already established");
  }

  p_ = std::make_unique<broker::peering>(ep_->peer(ip, port));

  // Wait for message
  pollfd pfd{ep_->outgoing_connection_status().fd(), POLLIN, 0};
  int poll_code = poll(&pfd, 1, timeout);
  if (poll_code < 0) {
    return Status(1, "poll error returned connecting to bro endpoint");
  }

  if (poll_code == 0) {
    return Status(1, "Connecting to bro endpoint timed out");
  }

  broker::outgoing_connection_status::tag status;
  Status s = getOutgoingConnectionStatusChange(status, false);
  if (!s.ok()) {
    return s;
  }
  if (status == broker::outgoing_connection_status::tag::incompatible) {
    return Status(1, "Cannot peer because broker versions are incompatible");
  }
  if (status == broker::outgoing_connection_status::tag::disconnected) {
    return Status(1, "Cannot peer because broker connection was disconnected");
  }

  return Status(0, "OK");
}

Status BrokerManager::unpeer() {
  if (p_ != nullptr) {
    ep_->unpeer(*p_);

    p_ = nullptr;

    broker::outgoing_connection_status::tag status;
    Status s = getOutgoingConnectionStatusChange(status, false);
    if (s.getCode() == 1 or
        status != broker::outgoing_connection_status::tag::disconnected) {
      return Status(1, "Unable to disconnect broker connection");
    }
  }

  return Status(0, "OK");
}

Status BrokerManager::getOutgoingConnectionStatusChange(
    broker::outgoing_connection_status::tag& status, bool block) {
  std::deque<broker::outgoing_connection_status> conn_status;
  if (block) {
    conn_status = ep_->outgoing_connection_status().need_pop();
  } else {
    conn_status = ep_->outgoing_connection_status().want_pop();
  }
  if (conn_status.size() < 1) {
    return Status(1, "Connecting to bro endpoint timed out");
  }

  if (conn_status.size() > 1) {
    LOG(WARNING) << "Received multiple connection updates";
  }

  // conn_status.size() == 1
  status = conn_status.back().status;
  return Status(0, "OK");
}

Status BrokerManager::announce() {
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
  Status s = sendEvent(TOPIC_ANNOUNCE, announceMsg);
  if (!s.ok()) {
    return s;
  }

  return Status(0, "OK");
}

int BrokerManager::getOutgoingConnectionFD() {
  if (ep_ == nullptr) {
    return -1;
  }
  return ep_->outgoing_connection_status().fd();
}

Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli) {
  const auto& queryID = qli.name;

  // Is this schedule or one-time? Get Query and Type
  std::string query = "";
  std::string qType = "";
  auto status_find =
      QueryManager::get().findQueryAndType(queryID, qType, query);
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
  const auto& topic = QueryManager::get().getEventTopic(queryID);
  const auto& event_name = QueryManager::get().getEventName(queryID);
  VLOG(1) << "Creating " << rows.size() << " messages with event name '"
          << event_name << "'";

  // Create message for each row
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
         broker::record::field(
             broker::data(QueryManager::get().getEventCookie(queryID)))});
    msg.push_back(broker::data(result_info));

    // Format each column
    for (const auto& t : columns) {
      const auto& colName = std::get<0>(t);
      if (row.count(colName) != 1) {
        LOG(ERROR) << "Column '" << colName << "' not present in results for '"
                   << event_name << "'";
        break;
      }
      const auto& value = row.at(colName);

      try {
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
          msg.push_back(
              broker::data(AS_LITERAL(UNSIGNED_BIGINT_LITERAL, value)));
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
      } catch (const boost::bad_lexical_cast& e) {
        LOG(ERROR) << "Skip result for query ID '" << queryID
                   << "' because value '" << value << "' (Column: " << colName
                   << ") cannot be parsed as '"
                   << kColumnTypeNames.at(columnTypes.at(colName)) << '"';
        break;
      }
    }

    // Send event message
    sendEvent(topic, msg);
  }

  // Delete one-time query information
  if (qType == "ONETIME") {
    QueryManager::get().removeQueryEntry(query);
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
