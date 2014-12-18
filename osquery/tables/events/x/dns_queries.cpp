/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <glog/logging.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include "osquery/events/x/pcap.h"

namespace osquery {
namespace tables {

/**
 * @brief Track time, action changes to /etc/passwd
 *
 * This is mostly an example EventSubscriber implementation.
 */
class DnsQueriesEventSubscriber : public EventSubscriber<PcapEventPublisher> {
  DECLARE_SUBSCRIBER("DnsQueriesEventSubscriber");

 public:
  void init();

  Status Callback(const PcapEventContextRef& ec);
};

REGISTER_EVENTSUBSCRIBER(DnsQueriesEventSubscriber);

void DnsQueriesEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->interface = "any";

  subscribe(&DnsQueriesEventSubscriber::Callback, sc);
}

Status DnsQueriesEventSubscriber::Callback(const PcapEventContextRef& ec) {
  return Status(0, "OK");
}
}
}
