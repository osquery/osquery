/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <pwd.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

FLAG(bool,
     disable_endpointsecurity,
     true,
     "Disable receiving events from the EndpointSecurity subsystem");

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
    switch (result) {
    case ES_NEW_CLIENT_RESULT_SUCCESS: {
      es_client_success_ = true;
    }
      return Status::success();
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
      return Status::failure(1, "invalid argument");
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
      return Status::failure(1, "EndpointSecurity client cannot communicate");
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
          1, "Too many EndpointSecurity clients running on the system");
    default:
      return Status::failure(1, "EndpointSecurity: Unknown error");
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
    es_delete_client(es_client_);
    es_client_ = nullptr;
  }
}

static inline std::string getPath(const es_process_t* p) {
  return p->executable->path.length > 0 ? p->executable->path.data : "";
}

static inline std::string getSigningId(const es_process_t* p) {
  return p->signing_id.length > 0 && p->signing_id.data != nullptr
             ? p->signing_id.data
             : "";
}

static inline std::string getTeamId(const es_process_t* p) {
  return p->team_id.length > 0 && p->team_id.data != nullptr ? p->team_id.data
                                                             : "";
}

static inline std::string getStringFromToken(es_string_token_t* t) {
  return t->length > 0 && t->data != nullptr ? t->data : "";
}

static inline std::string getCwdPathFromPid(pid_t pid) {
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

static inline void getProperties(const es_process_t* p,
                                 const EndpointSecurityEventContextRef& ec) {
  auto audit_token = p->audit_token;
  ec->pid = audit_token_to_pid(audit_token);
  ec->parent = p->ppid;
  ec->original_parent = p->original_ppid;

  ec->path = getPath(p);
  ec->cwd = getCwdPathFromPid(ec->pid);

  ec->uid = audit_token_to_ruid(audit_token);
  ec->euid = audit_token_to_egid(audit_token);
  ec->gid = audit_token_to_rgid(audit_token);
  ec->egid = audit_token_to_egid(audit_token);

  ec->signing_id = getSigningId(p);
  ec->team_id = getTeamId(p);
  ec->cdhash = getCDHash(p);
  ec->platform_binary = p->is_platform_binary;

  auto user = getpwuid(ec->uid);
  ec->username = user->pw_name != nullptr ? std::string(user->pw_name) : "";

  ec->cwd = getCwdPathFromPid(ec->pid);
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

  getProperties(message->process, ec);

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    ec->es_event = ES_EVENT_TYPE_NOTIFY_EXEC;
    ec->event_type = "exec";

    getProperties(message->event.exec.target, ec);
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
