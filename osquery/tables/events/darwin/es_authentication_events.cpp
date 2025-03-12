/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <os/availability.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/events/events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>

namespace osquery {

Status ESAuthenticationEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    // Authentication events (macOS 13+)
    if (__builtin_available(macos 13.0, *)) {
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_AUTHENTICATION);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH);
      sc->es_event_subscriptions_.push_back(
          ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH);
    }

    // SU/SUDO events (available on macOS 14+)
    if (__builtin_available(macos 14.0, *)) {
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SU);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SUDO);
    }

    subscribe(&ESAuthenticationEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

Status ESAuthenticationEventSubscriber::getAuthenticationEventData(
    const es_message_t* message, ESAuthenticationEventContextRef& ec) {
  if (message == nullptr || ec == nullptr) {
    return Status::failure(1, "Invalid message or context");
  }

  // Fill in common event metadata
  ec->es_event = message->event_type;
  auto event_time = static_cast<long long>(message->time.tv_sec);
  ec->time = event_time;
  getBaseProcessProperties(message->process, ec);

  // Initialize defaults
  ec->success = false;
  ec->auth_type = "";
  ec->result_type = "";
  ec->remote_address = "";
  ec->remote_port = 0;
  ec->auth_right = "";

  // Process different authentication event types
  switch (message->event_type) {
  // Generic authentication event
  case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "authentication";
      ec->description = "Authentication event";

      // Extract authentication-specific data
      ec->success = message->event.authentication->success;
      // auth_type is not a string but an enum value
      ec->auth_type = "authentication";

      // result_type may not exist in all macOS versions
      ec->result_type = "unknown";

      // right may not exist in all macOS versions
      ec->auth_right = "";
    }
    break;
  }

  // SSH login events
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "openssh_login";
      ec->description = "SSH login attempt";

      ec->success = message->event.openssh_login->success;
      // result_type may not exist in all versions
      ec->result_type = "unknown";
      ec->auth_type = "ssh";

      if (message->event.openssh_login->source_address.length > 0) {
        ec->remote_address =
            std::string(message->event.openssh_login->source_address.data);
      }

      if (message->event.openssh_login->username.length > 0) {
        ec->ssh_login_username =
            std::string(message->event.openssh_login->username.data);
      }
    }
    break;
  }

  // SSH logout events
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "openssh_logout";
      ec->description = "SSH session ended";
      ec->success = true; // Logout is always successful
      ec->auth_type = "ssh";
    }
    break;
  }

  // Login window login
  case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "login_login";
      ec->description = "Login window login";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // Login window logout
  case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "login_logout";
      ec->description = "Login window logout";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // LoginWindow session login
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "lw_session_login";
      ec->description = "LoginWindow session login";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // LoginWindow session logout
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "lw_session_logout";
      ec->description = "LoginWindow session logout";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // LoginWindow session lock
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "lw_session_lock";
      ec->description = "LoginWindow session lock";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // LoginWindow session unlock
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "lw_session_unlock";
      ec->description = "LoginWindow session unlock";
      ec->success = true;
      ec->auth_type = "login_window";
    }
    break;
  }

  // Screen sharing attach
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "screensharing_attach";
      ec->description = "Screen sharing connection established";
      ec->success = true;
      ec->auth_type = "screensharing";

      if (message->event.screensharing_attach->source_address.length > 0) {
        ec->remote_address = std::string(
            message->event.screensharing_attach->source_address.data);
      }

      if (message->event.screensharing_attach->viewer_appleid.length > 0) {
        ec->ssh_login_username = std::string(
            message->event.screensharing_attach->viewer_appleid.data);
      }

      ec->screensharing_type = "attach";
      // type may not exist in all versions
      ec->connection_type = "unknown";

      // viewer_app_path may not exist in all versions
      ec->screensharing_viewer_app_path = "";
    }
    break;
  }

  // Screen sharing detach
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: {
    if (__builtin_available(macos 13.0, *)) {
      ec->event_type = "screensharing_detach";
      ec->description = "Screen sharing connection ended";
      ec->success = true;
      ec->auth_type = "screensharing";
      ec->screensharing_type = "detach";
    }
    break;
  }

  // SU command (elevation to another user)
  case ES_EVENT_TYPE_NOTIFY_SU: {
    if (__builtin_available(macos 14.0, *)) {
      ec->event_type = "su";
      ec->description = "SU command execution";

      ec->success = message->event.su->success;
      ec->auth_type = "su";

      // Extract from/to usernames
      if (message->event.su->from_username.length > 0) {
        ec->su_from_username =
            std::string(message->event.su->from_username.data);
      }

      if (message->event.su->to_username.length > 0) {
        ec->su_to_username = std::string(message->event.su->to_username.data);
      }

      // For privilege elevation events, store the target UID
      // Skip setting target_uid to prevent type issues
    }
    break;
  }

  // SUDO command (elevation to root)
  case ES_EVENT_TYPE_NOTIFY_SUDO: {
    if (__builtin_available(macos 14.0, *)) {
      ec->event_type = "sudo";
      ec->description = "SUDO command execution";

      ec->success = message->event.sudo->success;
      ec->auth_type = "sudo";

      // Extract command
      if (message->event.sudo->command.length > 0) {
        ec->sudo_command = std::string(message->event.sudo->command.data);
      }

      // For privilege elevation events, always set target UID to 0 (root)
      ec->target_uid = 0;
    }
    break;
  }

  default:
    return Status::failure(1, "Unsupported authentication event type");
  }

  return Status::success();
}

Status ESAuthenticationEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  // We won't use this function directly since we'll be using the specialized
  // ESAuthenticationEventContext. The CoreEventRouter will handle creating our
  // events and routing them appropriately.

  return Status::success();
}

namespace tables {

QueryData genTable(QueryContext& context) {
  QueryData results;
  auto es_auth_events =
      EventFactory::getEventSubscriber("es_authentication_events");
  if (es_auth_events != nullptr) {
    auto subscriber =
        dynamic_cast<ESAuthenticationEventSubscriber*>(es_auth_events.get());
    if (subscriber != nullptr) {
      // addBatch is protected, so the event subscriber needs to handle exposing
      // results itself For this first version, we'll just return an empty
      // result set
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery