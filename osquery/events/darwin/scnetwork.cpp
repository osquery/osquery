/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/events/darwin/scnetwork.h"

namespace osquery {

REGISTER(SCNetworkEventPublisher, "event_publisher", "scnetwork");

void SCNetworkEventPublisher::tearDown() {
  stop();

  WriteLock lock(mutex_);
  clearAll();
  run_loop_ = nullptr;
}

void SCNetworkEventPublisher::Callback(const SCNetworkReachabilityRef target,
                                       SCNetworkReachabilityFlags flags,
                                       void* info) {
  auto ec = createEventContext();
  ec->subscription = *(SCNetworkSubscriptionContextRef*)info;
  ec->flags = flags;
}

bool SCNetworkEventPublisher::shouldFire(
    const SCNetworkSubscriptionContextRef& sc,
    const SCNetworkEventContextRef& ec) const {
  // Only fire the event for the subscription context it matched.
  return (sc == ec->subscription);
}

void SCNetworkEventPublisher::addTarget(
    const SCNetworkSubscriptionContextRef& sc,
    const SCNetworkReachabilityRef& target) {
  targets_.push_back(target);

  // Assign a context (the subscription context) to the target.
  SCNetworkReachabilityContext* context = new SCNetworkReachabilityContext();
  context->info = (void*)&sc;
  context->retain = nullptr;
  context->release = nullptr;
  contexts_.push_back(context);

  SCNetworkReachabilitySetCallback(
      target, SCNetworkEventPublisher::Callback, context);
}

void SCNetworkEventPublisher::addHostname(
    const SCNetworkSubscriptionContextRef& sc) {
  auto target =
      SCNetworkReachabilityCreateWithName(nullptr, sc->target.c_str());
  target_names_.push_back(sc->target);
  addTarget(sc, target);
}

void SCNetworkEventPublisher::addAddress(
    const SCNetworkSubscriptionContextRef& sc) {
  struct sockaddr* addr;
  if (sc->family == AF_INET) {
    struct sockaddr_in ipv4_addr;
    ipv4_addr.sin_family = AF_INET;
    inet_pton(AF_INET, sc->target.c_str(), &ipv4_addr.sin_addr);
    addr = (struct sockaddr*)&ipv4_addr;
  } else {
    struct sockaddr_in6 ip6_addr;
    ip6_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, sc->target.c_str(), &ip6_addr.sin6_addr);
    addr = (struct sockaddr*)&ip6_addr;
  }

  auto target = SCNetworkReachabilityCreateWithAddress(nullptr, addr);
  target_addresses_.push_back(sc->target);
  addTarget(sc, target);
}

void SCNetworkEventPublisher::clearAll() {
  for (auto& target : targets_) {
    CFRelease(target);
  }
  targets_.clear();

  for (auto& context : contexts_) {
    delete context;
  }
  contexts_.clear();

  target_names_.clear();
  target_addresses_.clear();
}

void SCNetworkEventPublisher::configure() {
  // Must stop before clearing contexts.
  stop();

  {
    WriteLock lock(mutex_);
    // Clear all targets.
    clearAll();

    for (const auto& sub : subscriptions_) {
      auto sc = getSubscriptionContext(sub->context);
      if (sc->type == ADDRESS_TARGET) {
        auto existing_address = std::find(
            target_addresses_.begin(), target_addresses_.end(), sc->target);
        if (existing_address != target_addresses_.end()) {
          // Add the address target.
          addAddress(sc);
        }
      } else {
        auto existing_hostname =
            std::find(target_names_.begin(), target_names_.end(), sc->target);
        if (existing_hostname != target_names_.end()) {
          // Add the hostname target.
          addHostname(sc);
        }
      }
    }

    // Make sure at least one target exists.
    if (targets_.empty()) {
      auto sc = createSubscriptionContext();
      sc->type = NAME_TARGET;
      sc->target = "localhost";
      addHostname(sc);
    }
  }

  restart();
}

void SCNetworkEventPublisher::restart() {
  if (run_loop_ == nullptr) {
    return;
  }

  stop();

  WriteLock lock(mutex_);
  for (const auto& target : targets_) {
    SCNetworkReachabilityScheduleWithRunLoop(
        target, run_loop_, kCFRunLoopDefaultMode);
  }
}

void SCNetworkEventPublisher::stop() {
  if (run_loop_ == nullptr) {
    // No need to stop if there is not run loop.
    return;
  }

  WriteLock lock(mutex_);
  for (const auto& target : targets_) {
    SCNetworkReachabilityUnscheduleFromRunLoop(
        target, run_loop_, kCFRunLoopDefaultMode);
  }

  // Stop the run loop.
  CFRunLoopStop(run_loop_);
}

Status SCNetworkEventPublisher::run() {
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();
  return Status::success();
}
};
