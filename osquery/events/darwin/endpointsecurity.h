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

// Base class for all EndpointSecurity event contexts
struct BaseESEventContext : public EventContext {
  es_event_type_t es_event;
  int version;
  long seq_num;
  long global_seq_num;

  std::string event_type;
  std::string category;
  std::string severity;

  pid_t pid;
  int pidversion;

  std::string path;
  std::string username;
  std::string description;

  // Event ID serves as a unique identifier for correlation
  std::string eid;
};

using BaseESEventContextRef = std::shared_ptr<BaseESEventContext>;

// Base class for all EndpointSecurity subscription contexts
struct BaseESSubscriptionContext : public SubscriptionContext {
  std::vector<es_event_type_t> es_event_subscriptions_;
  std::vector<Row> row_list;
};

using BaseESSubscriptionContextRef = std::shared_ptr<BaseESSubscriptionContext>;

struct EndpointSecuritySubscriptionContext : public BaseESSubscriptionContext {
};

using EndpointSecuritySubscriptionContextRef =
    std::shared_ptr<EndpointSecuritySubscriptionContext>;

struct EndpointSecurityEventContext : public BaseESEventContext {
  pid_t parent;
  int parent_pidversion;
  pid_t original_parent;
  pid_t session_id;
  pid_t responsible_pid;
  int responsible_pidversion;

  std::string cwd;

  uid_t uid;
  uid_t euid;
  gid_t gid;
  gid_t egid;

  std::string signing_id;
  std::string team_id;
  std::string cdhash;
  bool platform_binary;
  std::string codesigning_flags;

  std::string executable;

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

struct EndpointSecurityFileSubscriptionContext
    : public BaseESSubscriptionContext {
  std::vector<es_event_type_t> es_file_event_subscriptions_;
};

using EndpointSecurityFileSubscriptionContextRef =
    std::shared_ptr<EndpointSecurityFileSubscriptionContext>;

struct EndpointSecurityFileEventContext : BaseESEventContext {
  std::string filename;
  std::string dest_filename;

  // Add process information fields
  pid_t parent = 0; // Default to 0 if not available
};

using EndpointSecurityFileEventContextRef =
    std::shared_ptr<EndpointSecurityFileEventContext>;

// Authentication Events subscription context and event context
struct ESAuthenticationSubscriptionContext : public BaseESSubscriptionContext {
};

using ESAuthenticationSubscriptionContextRef =
    std::shared_ptr<ESAuthenticationSubscriptionContext>;

struct ESAuthenticationEventContext : public BaseESEventContext {
  bool success;
  std::string auth_type;
  std::string result_type;
  std::string auth_right;
  std::string remote_address;
  int remote_port;

  // Specific fields for SSH login events
  std::string ssh_login_username;

  // Specific fields for su/sudo events
  std::string su_from_username;
  std::string su_to_username;
  std::string sudo_command;

  // Specific fields for screensharing events
  std::string screensharing_type;
  std::string screensharing_viewer_app_path;
  std::string connection_type;

  // Specific fields for profile events
  std::string profile_identifier;
  std::string profile_uuid;

  // Target UID for privilege events
  uid_t target_uid;
};

using ESAuthenticationEventContextRef =
    std::shared_ptr<ESAuthenticationEventContext>;

// Core event category system
// These help determine which subscriber should handle each event
enum class ESEventCategory {
  PROCESS,
  AUTHENTICATION,
  NETWORK,
  FILE,
  PRIVILEGE,
  SYSTEM
};

// Function to determine the category of an event
ESEventCategory categorizeESEvent(es_event_type_t event_type);

// Core router for EndpointSecurity events
class CoreEventRouter {
 public:
  static void routeEvent(const es_message_t* message,
                         const BaseESEventContextRef& ec);
};

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
  std::vector<std::string> file_paths_;
  std::vector<std::string> exclude_paths_;
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

// ES Authentication Events Subscriber
class ESAuthenticationEventSubscriber
    : public EventSubscriber<EndpointSecurityPublisher> {
 public:
  ESAuthenticationEventSubscriber() {
    setName("es_authentication_events");
  }

  Status init() override API_AVAILABLE(macos(10.15));
  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc)
      API_AVAILABLE(macos(10.15));

  static Status getAuthenticationEventData(const es_message_t* message,
                                           ESAuthenticationEventContextRef& ec);

  void genTable(RowYield& yield, QueryContext& context);
};

} // namespace osquery
