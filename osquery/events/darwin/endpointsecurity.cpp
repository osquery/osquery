/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <uuid/uuid.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);
DECLARE_bool(enable_es_authentication_events);

// Forward declarations
class ESAuthenticationEventSubscriber;

REGISTER(EndpointSecurityPublisher, "event_publisher", "endpointsecurity")
REGISTER(ESAuthenticationEventSubscriber,
         "event_subscriber",
         "es_authentication_events");

// Event categorization function
ESEventCategory categorizeESEvent(es_event_type_t event_type) {
  // Authentication events
  if (event_type == ES_EVENT_TYPE_NOTIFY_AUTHENTICATION ||
      event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN ||
      event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT ||
      event_type == ES_EVENT_TYPE_NOTIFY_SU ||
      event_type == ES_EVENT_TYPE_NOTIFY_SUDO ||
      event_type == ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH ||
      event_type == ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH ||
      event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN ||
      event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT ||
      event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN ||
      event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT ||
      event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK ||
      event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK) {
    return ESEventCategory::AUTHENTICATION;
  }

  // Process events
  if (event_type == ES_EVENT_TYPE_NOTIFY_EXEC ||
      event_type == ES_EVENT_TYPE_NOTIFY_FORK ||
      event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
    return ESEventCategory::PROCESS;
  }

  // Network events
  if (event_type == ES_EVENT_TYPE_NOTIFY_SOCKET ||
      event_type == ES_EVENT_TYPE_NOTIFY_CONNECT ||
      event_type == ES_EVENT_TYPE_NOTIFY_BIND ||
      event_type == ES_EVENT_TYPE_NOTIFY_LISTEN ||
      event_type == ES_EVENT_TYPE_NOTIFY_ACCEPT ||
      event_type == ES_EVENT_TYPE_NOTIFY_UIPC_BIND ||
      event_type == ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT) {
    return ESEventCategory::NETWORK;
  }

  // File events
  if (event_type == ES_EVENT_TYPE_NOTIFY_MOUNT ||
      event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETACL ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETATTRLIST ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETEXTATTR ||
      event_type == ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR ||
      event_type == ES_EVENT_TYPE_NOTIFY_LISTEXTATTR ||
      event_type == ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR ||
      event_type == ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA ||
      event_type == ES_EVENT_TYPE_NOTIFY_CHROOT ||
      event_type == ES_EVENT_TYPE_NOTIFY_UTIMES ||
      event_type == ES_EVENT_TYPE_NOTIFY_CHMOD ||
      event_type == ES_EVENT_TYPE_NOTIFY_CHOWN) {
    return ESEventCategory::FILE;
  }

  // Privilege events
  if (event_type == ES_EVENT_TYPE_NOTIFY_SETUID ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETEUID ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETREUID ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETGID ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETEGID ||
      event_type == ES_EVENT_TYPE_NOTIFY_SETREGID) {
    return ESEventCategory::PRIVILEGE;
  }

  // Default to SYSTEM for any other events
  return ESEventCategory::SYSTEM;
}

// Generate a unique event ID for correlation
std::string generateEventId() {
  uuid_t uuid;
  char uuid_str[37] = {0};

  uuid_generate(uuid);
  uuid_unparse(uuid, uuid_str);

  return std::string(uuid_str);
}

// Core event router implementation
void CoreEventRouter::routeEvent(const es_message_t* message,
                                 const BaseESEventContextRef& ec) {
  if (message == nullptr || ec == nullptr) {
    return;
  }

  // Determine the category of the event
  auto category = categorizeESEvent(message->event_type);

  // Route based on category
  switch (category) {
  case ESEventCategory::AUTHENTICATION: {
    if (FLAGS_enable_es_authentication_events) {
      // Convert to authentication event context and populate specific fields
      auto auth_ec = std::make_shared<ESAuthenticationEventContext>();

      // Copy base properties from the original context
      auth_ec->es_event = ec->es_event;
      auth_ec->version = ec->version;
      auth_ec->seq_num = ec->seq_num;
      auth_ec->global_seq_num = ec->global_seq_num;
      auth_ec->event_type = ec->event_type;
      auth_ec->pid = ec->pid;
      auth_ec->pidversion = ec->pidversion;
      auth_ec->path = ec->path;
      auth_ec->username = ec->username;

      // Set category and default severity
      auth_ec->category = "authentication";
      auth_ec->severity = "medium";

      // Generate a unique event ID
      auth_ec->eid = generateEventId();

      // Get specific authentication event data (implemented in the subscriber)
      ESAuthenticationEventSubscriber::getAuthenticationEventData(message,
                                                                  auth_ec);

      // Fire the event to authentication event subscribers
      EventFactory::fire<EndpointSecurityPublisher>(auth_ec);
    }
    break;
  }

  // Currently we'll pass through for other event types
  // In subsequent PRs, we'll implement specific handlers for each category
  case ESEventCategory::PROCESS:
  case ESEventCategory::NETWORK:
  case ESEventCategory::FILE:
  case ESEventCategory::PRIVILEGE:
  case ESEventCategory::SYSTEM:
  default:
    // If it's not a specialized event, just pass through to the original
    // publisher This maintains backward compatibility
    break;
  }
}

Status EndpointSecurityPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity) {
      return Status::failure(1,
                             "EndpointSecurity is disabled via configuration");
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_client_, handler);

    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
      es_client_success_ = true;
      return Status::success();
    } else {
      return Status::failure(1, getEsNewClientErrorMessage(result));
    }
  } else {
    return Status::failure(
        1, "EndpointSecurity is only available on macOS 10.15 and higher");
  }
}

void EndpointSecurityPublisher::configure() {
  if (es_client_ == nullptr) {
    return;
  }

  auto cache = es_clear_cache(es_client_);
  if (cache != ES_CLEAR_CACHE_RESULT_SUCCESS) {
    VLOG(1) << "Couldn't clear cache for EndpointSecurity client";
    return;
  }

  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto events = sc->es_event_subscriptions_;
    auto es_sub = es_subscribe(es_client_, &events[0], events.size());
    if (es_sub != ES_RETURN_SUCCESS) {
      VLOG(1) << "Couldn't subscribe to EndpointSecurity subsystem";
    }
  }
}

void EndpointSecurityPublisher::tearDown() {
  if (es_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_client_);

  if (es_client_success_) {
    auto result = es_delete_client(es_client_);
    if (result != ES_RETURN_SUCCESS) {
      VLOG(1) << "endpointsecurity: error tearing down es_client";
    }
    es_client_ = nullptr;
  }
}

void EndpointSecurityPublisher::handleMessage(const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }

  auto ec = createEventContext();

  ec->version = message->version;
  if (ec->version >= 2) {
    ec->seq_num = message->seq_num;
  }

  if (ec->version >= 4) {
    ec->global_seq_num = message->global_seq_num;
  }

  getProcessProperties(message->process, ec);

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_EXEC;
    ec->event_type = "exec";

    getProcessProperties(message->event.exec.target, ec);
    ec->argc = es_exec_arg_count(&message->event.exec);
    {
      std::stringstream args;
      for (auto i = 0; i < ec->argc; i++) {
        auto arg = es_exec_arg(&message->event.exec, i);
        auto s = getStringFromToken(&arg);
        appendQuotedString(args, s, ' ');
      }
      ec->args = args.str();
    }

    ec->envc = es_exec_env_count(&message->event.exec);
    {
      std::stringstream envs;
      for (auto i = 0; i < ec->envc; i++) {
        auto env = es_exec_env(&message->event.exec, i);
        auto s = getStringFromToken(&env);
        appendQuotedString(envs, s, ' ');
      }
      ec->envs = envs.str();
    }

    if (ec->version >= 3) {
      ec->cwd = getStringFromToken(&message->event.exec.cwd->path);
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_FORK: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_FORK;
    ec->event_type = "fork";
    ec->child_pid = audit_token_to_pid(message->event.fork.child->audit_token);
  } break;
  case ES_EVENT_TYPE_NOTIFY_EXIT: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_EXIT;
    ec->event_type = "exit";
    ec->exit_code = message->event.exit.stat;
  } break;
  default:
    break;
  }

  // First route to specialized handlers through the CoreEventRouter
  CoreEventRouter::routeEvent(message, ec);

  // Then continue with the original event flow for backward compatibility
  EventFactory::fire<EndpointSecurityPublisher>(ec);
}

bool EndpointSecurityPublisher::shouldFire(
    const EndpointSecuritySubscriptionContextRef& sc,
    const EndpointSecurityEventContextRef& ec) const {
  return true;
}

} // namespace osquery
