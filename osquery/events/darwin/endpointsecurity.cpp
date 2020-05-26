/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iomanip>

#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

namespace osquery {

FLAG(bool,
     disable_endpointsecurity,
     true,
     "Disable receiving events from the EndpointSecurity subsystem");

REGISTER(EndpointSecurityPublisher, "event_publisher", "endpointsecurity");

Status EndpointSecurityPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity) {
      return Status::failure(1, "ES disabled via configuration");
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_client_, handler);
    switch (result) {
    case ES_NEW_CLIENT_RESULT_SUCCESS: {
      es_client_success_ = true;
      auto ver = SQL::selectAllFrom("os_version");
      // check if macOS version is 10.15.4 or higher
      if (ver.front().at("major") == "10" && ver.front().at("minor") == "15" &&
          std::stoi(ver.front().at("patch")) >= 4) {
        macos_15_4_higher_ = true;
      }
    }
      return Status::success();
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
      return Status::failure(
          1, "Invalid args provided to EndpointSecurity client");
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
      return Status::failure(
          1, "EndpointSecurity client cannot communicate with ES subsystem");
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
      return Status::failure(1, "EndpointSecurity client lacks entitlement");
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
      return Status::failure(
          1, "EndpointSecurity client lacks user TCC permissions");
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
      return Status::failure(1,
                             "EndpointSecurity client is not running as root");
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
      return Status::failure(
          1, "Too many EndpointSecurity clients running on system");
    default:
      return Status::failure(1, "EndpointSecurity: Unknown Error");
    }
  } else {
    return Status::failure(1,
                           "EndpointSecurity is only available on macOS 10.15");
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
      VLOG(1) << "Couldn't subscribe to ES subsystem";
    }
  }
}

void EndpointSecurityPublisher::tearDown() {
  if (es_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_client_);

  // calling es_delete_client on macOS 10.15.0 - 10.15.3 leads to a crash
  if (es_client_success_ && macos_15_4_higher_) {
    es_delete_client(es_client_);
  }
}

static inline std::string getPath(const es_process_t* p) {
  return p->executable->path.length > 0 ? p->executable->path.data : "";
}

static inline std::string getSigningId(const es_process_t* p) {
  return p->signing_id.length > 0 ? p->signing_id.data : "";
}

static inline std::string getTeamId(const es_process_t* p) {
  return p->team_id.length > 0 ? p->team_id.data : "";
}

static inline std::string getStringFromToken(es_string_token_t* t) {
  return t->length > 0 && t->data != nullptr ? t->data : "";
}

static inline std::string getCwdPath(pid_t pid) {
  struct proc_vnodepathinfo vpi {};
  auto bytes = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
  return bytes <= 0 ? "" : vpi.pvi_cdir.vip_path;
}

static inline std::string getCDHash(const es_process_t* p) {
  std::stringstream hash;
  for (unsigned char i : p->cdhash) {
    hash << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<unsigned int>(i);
  }
  auto s = hash.str();
  return s.find_first_not_of(s.front()) == std::string::npos ? "" : s;
}

void EndpointSecurityPublisher::handleMessage(const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }
  auto ec = createEventContext();

  auto audit_token = message->process->audit_token;
  ec->pid = audit_token_to_pid(audit_token);
  ec->parent = message->process->ppid;
  ec->original_parent = message->process->original_ppid;

  ec->path = getPath(message->process);
  ec->cwd = getCwdPath(ec->pid);

  ec->uid = audit_token_to_ruid(audit_token);
  ec->euid = audit_token_to_euid(audit_token);
  ec->gid = audit_token_to_ruid(audit_token);
  ec->egid = audit_token_to_egid(audit_token);

  ec->signing_id = getSigningId(message->process);
  ec->team_id = getTeamId(message->process);
  ec->cdhash = getCDHash(message->process);
  ec->platform_binary = message->process->is_platform_binary;

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_EXEC;
    ec->event_type = "exec";

    // process command line arguments
    ec->argc = es_exec_arg_count(&message->event.exec);
    std::stringstream args;
    for (auto i = 0; i < ec->argc; i++) {
      auto arg = es_exec_arg(&message->event.exec, i);
      auto s = getStringFromToken(&arg);
      args << s << " ";
    }
    ec->args = args.str();

    // process env variables
    ec->envc = es_exec_env_count(&message->event.exec);
    std::stringstream envs;
    for (auto i = 0; i < ec->envc; i++) {
      auto env = es_exec_env(&message->event.exec, i);
      auto s = getStringFromToken(&env);
      envs << s << " ";
    }
    ec->envs = envs.str();
  } break;
  case ES_EVENT_TYPE_NOTIFY_FORK:
    ec->es_event = ES_EVENT_TYPE_NOTIFY_FORK;
    ec->event_type = "fork";
    ec->child_pid = audit_token_to_pid(message->event.fork.child->audit_token);
    break;
  case ES_EVENT_TYPE_NOTIFY_EXIT:
    ec->es_event = ES_EVENT_TYPE_NOTIFY_EXIT;
    ec->event_type = "exit";
    ec->exit_code = message->event.exit.stat;
    break;
  default:
    break;
  }

  EventFactory::fire<EndpointSecurityPublisher>(ec);
}

bool EndpointSecurityPublisher::shouldFire(
    const EndpointSecuritySubscriptionContextRef& sc,
    const EndpointSecurityEventContextRef& ec) const {
  // fire only if the event is one of the subscribed ones
  if (std::find(sc->es_event_subscriptions_.begin(),
                sc->es_event_subscriptions_.end(),
                ec->es_event) != sc->es_event_subscriptions_.end()) {
    return true;
  }
  return false;
}
} // namespace osquery
