// Copyright 2004-present Facebook. All Rights Reserved.

#include <arpa/inet.h>
#include <netinet/in.h>

#include "osquery/events/darwin/scnetwork.h"

#include <glog/logging.h>

namespace osquery {

REGISTER_EVENTPUBLISHER(SCNetworkEventPublisher);

void SCNetworkEventPublisher::tearDown() {
  for (auto target : targets_) {
    CFRelease(target);
  }
  targets_.clear();

  for (auto context : contexts_) {
    CFRelease(context);
  }
  contexts_.clear();
}

void SCNetworkEventPublisher::Callback(SCNetworkReachabilityRef target,
                                       SCNetworkReachabilityFlags flags,
                                       void* info) {
  auto ec = createEventContext();
  ec->subscription = *(SCNetworkSubscriptionContextRef*)info;
  ec->flags = flags;
}

bool SCNetworkEventPublisher::shouldFire(
    const SCNetworkSubscriptionContextRef sc,
    const SCNetworkEventContextRef ec) {
  // Only fire the event for the subscription context it matched.
  return (sc == ec->subscription);
}

void SCNetworkEventPublisher::addTarget(
    const SCNetworkSubscriptionContextRef sc,
    const SCNetworkReachabilityRef target) {
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
    const SCNetworkSubscriptionContextRef sc) {
  auto target = SCNetworkReachabilityCreateWithName(NULL, sc->target.c_str());
  target_names_.push_back(sc->target);
  addTarget(sc, target);
}

void SCNetworkEventPublisher::addAddress(
    const SCNetworkSubscriptionContextRef sc) {
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

  auto target = SCNetworkReachabilityCreateWithAddress(NULL, addr);
  target_addresses_.push_back(sc->target);
  addTarget(sc, target);
}

void SCNetworkEventPublisher::configure() {
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

  restart();
}

void SCNetworkEventPublisher::restart() {
  stop();

  if (run_loop_ == nullptr) {
    // Cannot schedule.
    return;
  }

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

  for (const auto& target : targets_) {
    SCNetworkReachabilityUnscheduleFromRunLoop(
        target, run_loop_, kCFRunLoopDefaultMode);
  }

  CFRunLoopStop(run_loop_);
}

Status SCNetworkEventPublisher::run() {
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();
  return Status(0, "OK");
}
};
