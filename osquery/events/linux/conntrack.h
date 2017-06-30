/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <vector>

#include <fnmatch.h>
#include <linux/limits.h>
#include <poll.h>

#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <osquery/events.h>

namespace osquery {

/**
 * @brief Subscription details for ConntrackEventPublisher events.
 *
 */
struct ConntrackSubscriptionContext : public SubscriptionContext {
  //TODO: Any subscription specific parameters? E.g. event types?
};

/**
 * @brief Event details for ConntrackEventPublisher events.
 */
struct ConntrackEventContext : public EventContext {
  /// The nf_conntrack structure if the EventSubscriber want to interact.
  std::shared_ptr<struct nf_conntrack> event{nullptr};
  /// A nf_conntrack_msg_type action representing the event type (NEW, UPDATE, DESTROY).
  enum nf_conntrack_msg_type type;
};

using ConntrackSubscriptionContextRef = std::shared_ptr<ConntrackSubscriptionContext>;
using ConntrackEventContextRef = std::shared_ptr<ConntrackEventContext>;

/**
 * @brief A Linux `conntrack` EventPublisher.
 *
 * This EventPublisher is retrieving its data from the netlink subsystem over netlink.
 * Conntrack tracks the connection status of network flows.
 */
class ConntrackEventPublisher
    : public EventPublisher<ConntrackSubscriptionContext, ConntrackEventContext> {
  DECLARE_PUBLISHER("conntrack");

 public:
  virtual ~ConntrackEventPublisher() {};

  /**
   *  @brief Creates initial connection to netfilter over netlink.
   */
  Status setUp() override;

  /// The configuration finished loading or was updated.
  void configure() override {};

  /// Release what initially was set up.
  void tearDown() override {};

  /// The calling for beginning the thread's run loop.
  Status run() override;

private:
  /// Helper/specialized event context creation.
  ConntrackEventContextRef createEventContextFrom(
          std::shared_ptr<struct nf_conntrack> event) const;

  /// The netlink socket from netlink_mnl
  std::shared_ptr<struct mnl_socket> nl_{nullptr};
};
}
