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

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/status_subscriber.hh>

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
  std::map<std::string, std::shared_ptr<broker::subscriber>> cp_queues{
      subscribers_};
  for (const auto& q : cp_queues) {
    Status s = deleteSubscriber(q.first);
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
  Status s = createSubscriber(TOPIC_PRE_GROUPS + group);
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

  return deleteSubscriber(TOPIC_PRE_GROUPS + group);
}

std::vector<std::string> BrokerManager::getGroups() {
  return groups_;
}

Status BrokerManager::createEndpoint(const std::string& ep_name) {
  if (ep_ != nullptr) {
    return Status(1, "Broker Endpoint already exists");
  }

  VLOG(1) << "Creating broker endpoint with name: " << ep_name;
  ep_ = std::make_unique<broker::endpoint>();
  return Status(0, "OK");
}

Status BrokerManager::createSubscriber(const std::string& topic) {
  if (ep_ == nullptr) {
    return Status(1, "Broker Endpoint does not exist");
  }

  if (subscribers_.count(topic) != 0) {
    return Status(1, "Message queue exists for topic '" + topic + "'");
  }

  VLOG(1) << "Creating message queue: " << topic;
  subscribers_[topic] =
      std::make_shared<broker::subscriber>(ep_->make_subscriber({topic}));

  return Status(0, "OK");
}

Status BrokerManager::deleteSubscriber(const std::string& topic) {
  if (subscribers_.count(topic) == 0) {
    return Status(1, "Message queue does not exist for topic '" + topic + "'");
  }

  // shared_ptr should delete the message_queue and unsubscribe from topic
  subscribers_.erase(subscribers_.find(topic));
  return Status(0, "OK");
}

std::shared_ptr<broker::subscriber> BrokerManager::getSubscriber(
    const std::string& topic) {
  return subscribers_.at(topic);
}

std::vector<std::string> BrokerManager::getTopics() {
  std::vector<std::string> topics;
  for (const auto& mq : subscribers_) {
    topics.push_back(mq.first);
  }
  return topics;
}

Status BrokerManager::peerEndpoint(const std::string& ip,
                                   int port,
                                   double timeout) {
  LOG(INFO) << "Connecting to Bro " << ip << ":" << port;
  // Check current connection state
  if (ep_ == nullptr) {
    return Status(1, "Broker Endpoint not set");
  }
  if (ss_ != nullptr) {
    return Status(1, "Broker connection already established");
  }

  // Connect endpoint and register for status updates and errors
  ss_ = std::make_unique<broker::status_subscriber>(
      ep_->make_status_subscriber(true));
  ep_->peer_nosync(ip, port, broker::timeout::seconds(-1));

  // Wait for connection status update
  LOG(WARNING) << "Waiting for Peering Status";
  auto st = getPeeringStatus(timeout);

  // Check connection status
  LOG(WARNING) << "Received Peering Status";
  if (st.code() != broker::sc::peer_added) {
    if (const auto stm = st.message()) {
      LOG(WARNING) << "Printing Peering Status";
      return Status(1, *stm);
    } else {
      LOG(WARNING) << "Unknown Peering Status";
      return Status(1, "Unknown connection state");
    }
  }

  return Status(0, "OK");
}

broker::status BrokerManager::getPeeringStatus(double timeout) {
  // Process latest status changes
  broker::detail::variant<broker::none, broker::error, broker::status> s;
  assert(broker::is<broker::none>(s));
  assert(!broker::is<broker::error>(s));
  assert(!broker::is<broker::status>(s));

  // Block first to wait for a status change to happen
  if (timeout != 0) {
    // with timeout
    if (timeout > 0) {
      auto s_opt = ss_->get(broker::to_duration(timeout));
      if (s_opt) {
        // Status received in time
        s = s_opt.value();
      }
    } else {
      // block until status change
      s = ss_->get();
    }
  }

  // Process any remaining change that is queued
  while (ss_->available()) {
    s = ss_->get();
  }

  // Evaluate the latest change (if any)
  // Check error
  if (auto err = broker::get_if<broker::error>(s)) {
    LOG(WARNING) << "Broker error:" << static_cast<int>(err->code()) << ", "
                 << to_string(*err);
    connection_status_ = {};
  }
  // Check status
  if (auto st = broker::get_if<broker::status>(s)) {
    connection_status_ = *st;
  }

  return connection_status_;
}

Status BrokerManager::unpeer() {
  // Check status subscriber
  if (ss_ == nullptr) {
    return Status(1, "No broker connection established");
  }

  // Check remote peer
  LOG(INFO) << "Number of peers to unpeer: " << ep_->peers().size();
  if (ep_ == nullptr || ep_->peers().size() == 0) {
    ss_ = nullptr;
    connection_status_ = {};
    LOG(INFO) << "No broker peers to disconnect";
    return Status(0, "No broker peers to disconnect");
  }

  // Disconnect peer(s)
  for (const auto& peer : ep_->peers()) {
    // Check for network info
    if (peer.peer.network) {
      auto netw = peer.peer.network.value();
      if (!ep_->unpeer(netw.address, netw.port)) {
        return Status(1, "Disconnect from remote endpoint was not successfull");
      }

      // Try to disconnect
      auto ps = BrokerManager::get().getPeeringStatus(3);
      if (ps.code() != broker::sc::peer_removed) {
        return Status(1, "Unable to unpeer");
      }
      LOG(INFO) << "Unpeered from " << netw.address << ":"
                << static_cast<int>(netw.port);

    } else {
      return Status(1,
                    "Cannot disconnect because remote endpoint has no network "
                    "information");
    }
  }

  LOG(INFO) << "Resetting ss_";
  ss_ = nullptr;
  connection_status_ = {};
  return Status(0, "OK");
}

Status BrokerManager::announce() {
  // Announce this endpoint to be a bro-osquery extension
  // Collect Groups
  broker::vector group_list;
  for (const auto& g : getGroups()) {
    group_list.push_back(broker::data(g));
  }

  // Create Message
  broker::bro::Event announceMsg(EVENT_HOST_NEW,
                                 {broker::data(getNodeID()), group_list});
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
  return ss_->fd();
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

    // Create message data header
    broker::vector msg_data;
    broker::vector result_info(
        {broker::data(uid),
         broker::data(broker::data(broker::enum_value{"osquery::" + trigger})),
         broker::data(QueryManager::get().getEventCookie(queryID))});
    msg_data.push_back(broker::data(result_info));

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
          msg_data.push_back(broker::data(value));
          break;
        }
        case ColumnType::TEXT_TYPE: {
          msg_data.push_back(broker::data(AS_LITERAL(TEXT_LITERAL, value)));
          break;
        }
        case ColumnType::INTEGER_TYPE: {
          msg_data.push_back(broker::data(AS_LITERAL(INTEGER_LITERAL, value)));
          break;
        }
        case ColumnType::BIGINT_TYPE: {
          msg_data.push_back(broker::data(AS_LITERAL(BIGINT_LITERAL, value)));
          break;
        }
        case ColumnType::UNSIGNED_BIGINT_TYPE: {
          msg_data.push_back(
              broker::data(AS_LITERAL(UNSIGNED_BIGINT_LITERAL, value)));
          break;
        }
        case ColumnType::DOUBLE_TYPE: {
          msg_data.push_back(broker::data(AS_LITERAL(DOUBLE_LITERAL, value)));
          break;
        }
        case ColumnType::BLOB_TYPE: {
          LOG(WARNING) << "Sending blob column type for column '" + colName +
                              "' as string";
          msg_data.push_back(broker::data(value));
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
    broker::bro::Event msg(event_name, msg_data);
    sendEvent(topic, msg);
  }

  // Delete one-time query information
  if (qType == "ONETIME") {
    QueryManager::get().removeQueryEntry(query);
  }

  return Status(0, "OK");
}

Status BrokerManager::sendEvent(const std::string& topic,
                                const broker::bro::Event& msg) {
  if (ep_ == nullptr) {
    return Status(1, "Endpoint not set");
  } else {
    VLOG(1) << "Sending Message '" << msg.name() << "' to  topic '" << topic
            << "'";
    ep_->publish(topic, msg);
  }

  return Status(0, "OK");
}
}
