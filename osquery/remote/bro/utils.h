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

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <osquery/status.h>
#include <osquery/system.h>

#include "osquery/remote/bro/query_manager.h"

namespace osquery {

Status createSubscriptionRequest(const std::string& rType,
                                 const broker::message& msg,
                                 const std::string& incoming_topic,
                                 SubscriptionRequest& sr);

Status parseBrokerGroups(const std::string& json_groups,
                         std::vector<std::string>& groups);

Status printQueryLogItem(const QueryLogItem& item);

void printDiffResults(const DiffResults& results);

void printQueryData(const QueryData& data);

void printDecorations(const std::map<std::string, std::string>& deco);
}
