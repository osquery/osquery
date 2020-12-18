/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/make_shared.hpp>

#include <SystemConfiguration/SCNetworkReachability.h>

#include <osquery/utils/status/status.h>

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

  short family{0};

  // Limit this target subscription to the set of flags.
  SCNetworkReachabilityFlags mask{0};
};

using SCNetworkSubscriptionContextRef =
    std::shared_ptr<SCNetworkSubscriptionContext>;

struct SCNetworkEventContext : public EventContext {
  SCNetworkSubscriptionContextRef subscription;
  SCNetworkReachabilityFlags flags;
};

using SCNetworkEventContextRef = std::shared_ptr<SCNetworkEventContext>;

/**
 * @brief An osquery EventPublisher for the Apple SCNetwork Reachability API.
 *
 * This exposes a lightweight network change monitoring capability.
 *
 */
class SCNetworkEventPublisher
    : public EventPublisher<SCNetworkSubscriptionContext,
                            SCNetworkEventContext> {
  DECLARE_PUBLISHER("scnetwork");

 public:
  SCNetworkEventPublisher(const std::string& name = "SCNetworkEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  void configure() override;

  Status setUp() override { return Status(1, "Publisher not used"); }
  void tearDown() override;

  // Entrypoint to the run loop
  Status run() override;

 public:
  /// SCNetwork registers a client callback instead of using a select/poll loop.
  static void Callback(const SCNetworkReachabilityRef target,
                       SCNetworkReachabilityFlags flags,
                       void* info);

 public:
  bool shouldFire(const SCNetworkSubscriptionContextRef& sc,
                  const SCNetworkEventContextRef& ec) const override;

 private:
  // Restart the run loop by calling configure.
  void restart();

  // Stop the run loop.
  void stop() override;

 private:
  void addHostname(const SCNetworkSubscriptionContextRef& sc);
  void addAddress(const SCNetworkSubscriptionContextRef& sc);
  void addTarget(const SCNetworkSubscriptionContextRef& sc,
                 const SCNetworkReachabilityRef& target);

  /// Helper method to clear all targets.
  void clearAll();

 private:
  /// Configured hostname targets.
  std::vector<std::string> target_names_;

  /// Configured host address targets.
  std::vector<std::string> target_addresses_;

  /// A container for all reachability targets.
  std::vector<SCNetworkReachabilityRef> targets_;

  /// A target-association context sortage.
  std::vector<SCNetworkReachabilityContext*> contexts_;

  /// This publisher thread's runloop.
  CFRunLoopRef run_loop_{nullptr};

  /// Storage/container operations protection mutex.
  mutable Mutex mutex_;
};
}
