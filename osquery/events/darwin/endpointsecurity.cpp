/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);

REGISTER(EndpointSecurityPublisher, "event_publisher", "endpointsecurity")

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
        args << s << ' ';
      }
      ec->args = args.str();
    }

    ec->envc = es_exec_env_count(&message->event.exec);
    {
      std::stringstream envs;
      for (auto i = 0; i < ec->envc; i++) {
        auto env = es_exec_env(&message->event.exec, i);
        auto s = getStringFromToken(&env);
        envs << s << ' ';
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

  EventFactory::fire<EndpointSecurityPublisher>(ec);
}

bool EndpointSecurityPublisher::shouldFire(
    const EndpointSecuritySubscriptionContextRef& sc,
    const EndpointSecurityEventContextRef& ec) const {
  return true;
}

} // namespace osquery
