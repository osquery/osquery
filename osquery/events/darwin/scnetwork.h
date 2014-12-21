/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <boost/make_shared.hpp>

#include <SystemConfiguration/SCNetworkReachability.h>

#include <osquery/status.h>
#include <osquery/events.h>

namespace osquery {

enum SCNetworkSubscriptionType {
  ADDRESS_TARGET = 0,
  NAME_TARGET = 1,
};

struct SCNetworkSubscriptionContext : public SubscriptionContext {
  // Target type.
  SCNetworkSubscriptionType type;
  // The hostname or address target for reachability monitoring.
  std::string target;
  short family;
  // Limit this target subscription to the set of flags.
  SCNetworkReachabilityFlags mask;
};

typedef std::shared_ptr<SCNetworkSubscriptionContext>
    SCNetworkSubscriptionContextRef;

struct SCNetworkEventContext : public EventContext {
  SCNetworkSubscriptionContextRef subscription;
  SCNetworkReachabilityFlags flags;
};

typedef std::shared_ptr<SCNetworkEventContext> SCNetworkEventContextRef;

/**
 * @brief An osquery EventPublisher for the Apple SCNetwork Reachability API.
 *
 * This exposes a lightweight network change monitoring capability.
 *
 */
class SCNetworkEventPublisher
    : public EventPublisher<SCNetworkSubscriptionContext,
                            SCNetworkEventContext> {
  DECLARE_PUBLISHER("SCNetworkEventPublisher");

 public:
  void configure();
  void tearDown();

  // Entrypoint to the run loop
  Status run();

 public:
  /// SCNetwork registers a client callback instead of using a select/poll loop.
  static void Callback(const SCNetworkReachabilityRef target,
                       SCNetworkReachabilityFlags flags,
                       void* info);

 public:
  SCNetworkEventPublisher() : EventPublisher(), run_loop_(nullptr) {}
  bool shouldFire(const SCNetworkSubscriptionContextRef& sc,
                  const SCNetworkEventContextRef& ec);

 private:
  // Restart the run loop by calling configure.
  void restart();
  // Stop the run loop.
  void stop();

 private:
  void addHostname(const SCNetworkSubscriptionContextRef& sc);
  void addAddress(const SCNetworkSubscriptionContextRef& sc);
  void addTarget(const SCNetworkSubscriptionContextRef& sc,
                 const SCNetworkReachabilityRef& target);

 private:
  std::vector<std::string> target_names_;
  std::vector<std::string> target_addresses_;
  std::vector<SCNetworkReachabilityRef> targets_;
  std::vector<SCNetworkReachabilityContext*> contexts_;
  CFRunLoopRef run_loop_;
};
}
