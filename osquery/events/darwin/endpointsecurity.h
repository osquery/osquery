/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <os/availability.h>

#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

struct EndpointSecuritySubscriptionContext : public SubscriptionContext {
  std::vector<es_event_type_t> es_event_subscriptions_;
};

using EndpointSecuritySubscriptionContextRef =
    std::shared_ptr<EndpointSecuritySubscriptionContext>;

struct EndpointSecurityEventContext : public EventContext {
  es_event_type_t es_event;

  // common event data
  std::string event_type;

  pid_t pid;
  pid_t parent;
  pid_t original_parent;

  std::string path;
  std::string cwd;

  uid_t uid;
  uid_t euid;
  gid_t gid;
  gid_t egid;

  std::string signing_id;
  std::string team_id;
  std::string cdhash;
  bool platform_binary;

  std::string executable;
  std::string username;

  // exec
  int argc;
  std::string args;

  int envc;
  std::string envs;

  // fork
  pid_t child_pid;

  // exit
  int exit_code;
};

using EndpointSecurityEventContextRef =
    std::shared_ptr<EndpointSecurityEventContext>;

class EndpointSecurityPublisher
    : public EventPublisher<EndpointSecuritySubscriptionContext,
                            EndpointSecurityEventContext> {
  DECLARE_PUBLISHER("endpointsecurity");

 public:
  explicit EndpointSecurityPublisher(
      const std::string& name = "EndpointSecurityPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  Status setUp() override API_AVAILABLE(macos(10.15));

  void configure() override API_AVAILABLE(macos(10.15));

  void tearDown() override API_AVAILABLE(macos(10.15));

  Status run() override API_AVAILABLE(macos(10.15)) {
    return Status::success();
  }

  bool shouldFire(const EndpointSecuritySubscriptionContextRef& sc,
                  const EndpointSecurityEventContextRef& ec) const override
      API_AVAILABLE(macos(10.15));

  virtual ~EndpointSecurityPublisher() API_AVAILABLE(macos(10.15)) {
    tearDown();
  }

 public:
  static void handleMessage(const es_message_t* message)
      API_AVAILABLE(macos(10.15));

 private:
  es_client_t* es_client_ = nullptr;
  bool es_client_success_{false};
  bool macos_15_4_higher_{false};
};
} // namespace osquery
