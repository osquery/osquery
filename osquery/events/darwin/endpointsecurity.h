/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <os/availability.h>

#include <osquery/core/flags.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/events.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/eventsubscriberplugin.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

struct EndpointSecuritySubscriptionContext : public SubscriptionContext {
  std::vector<es_event_type_t> es_event_subscriptions_;
  std::vector<Row> row_list;
};

using EndpointSecuritySubscriptionContextRef =
    std::shared_ptr<EndpointSecuritySubscriptionContext>;

struct EndpointSecurityEventContext : public EventContext {
  es_event_type_t es_event;
  int version;
  long seq_num;
  long global_seq_num;

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

struct EndpointSecurityFileSubscriptionContext : public SubscriptionContext {
  std::vector<es_event_type_t> es_file_event_subscriptions_;
  std::vector<Row> row_list;
};

using EndpointSecurityFileSubscriptionContextRef =
    std::shared_ptr<EndpointSecurityFileSubscriptionContext>;

struct EndpointSecurityFileEventContext : EndpointSecurityEventContext {
  es_event_type_t es_event;
  int version;
  long seq_num;
  long global_seq_num;

  std::string event_type;

  std::string filename;

  std::string dest_filename;
};

using EndpointSecurityFileEventContextRef =
    std::shared_ptr<EndpointSecurityFileEventContext>;

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
  es_client_s* es_client_{nullptr};
  bool es_client_success_{false};
};

class EndpointSecurityFileEventPublisher
    : public EventPublisher<EndpointSecurityFileSubscriptionContext,
                            EndpointSecurityFileEventContext> {
  DECLARE_PUBLISHER("endpointsecurity_fim");

 public:
  explicit EndpointSecurityFileEventPublisher(
      const std::string& name = "EndpointSecurityFileEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  Status setUp() override API_AVAILABLE(macos(10.15));

  void configure() override API_AVAILABLE(macos(10.15));

  void tearDown() override API_AVAILABLE(macos(10.15));

  Status run() override API_AVAILABLE(macos(10.15)) {
    return Status::success();
  }

  bool shouldFire(const EndpointSecurityFileSubscriptionContextRef& sc,
                  const EndpointSecurityFileEventContextRef& ec) const override
      API_AVAILABLE(macos(10.15));

  virtual ~EndpointSecurityFileEventPublisher() API_AVAILABLE(macos(10.15)) {
    tearDown();
  }

 public:
  static void handleMessage(const es_message_t* message)
      API_AVAILABLE(macos(10.15));

 private:
  es_client_s* es_file_client_{nullptr};
  bool es_file_client_success_{false};
  std::vector<std::string> muted_path_literals_;
  std::vector<std::string> muted_path_prefixes_;
  // clang-format off
  std::vector<std::string> default_muted_path_literals_ = {
      "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
      "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
      "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/tccd",
      "/usr/sbin/cfprefsd",
      "/usr/sbin/securityd",
      "/usr/libexec/opendirectoryd",
      "/usr/libexec/sandboxd",
      "/usr/libexec/syspolicyd",
      "/usr/libexec/runningboardd",
      "/usr/libexec/amfid",
      "/usr/libexec/watchdogd",
  };
  // clang-format on 
};

class ESProcessEventSubscriber
    : public EventSubscriber<EndpointSecurityPublisher> {
 public:
  ESProcessEventSubscriber() {
    setName("es_process_events");
  }

  Status init() override API_AVAILABLE(macos(10.15));
  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc)
      API_AVAILABLE(macos(10.15));
};

class ESProcessFileEventSubscriber
    : public EventSubscriber<EndpointSecurityFileEventPublisher> {
 public:
  ESProcessFileEventSubscriber() {
    setName("es_process_file_events");
  }

  Status init() override API_AVAILABLE(macos(10.15));
  Status Callback(const EndpointSecurityFileEventContextRef& ec,
                  const EndpointSecurityFileSubscriptionContextRef& sc)
      API_AVAILABLE(macos(10.15));
};
} // namespace osquery
