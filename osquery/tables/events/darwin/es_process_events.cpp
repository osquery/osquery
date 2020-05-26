/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <os/availability.h>

#include <osquery/events.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/flags.h>
#include <osquery/registry_factory.h>

namespace osquery {

class ESProcessEventSubscriber
    : public EventSubscriber<EndpointSecurityPublisher> {
 public:
  Status init() override API_AVAILABLE(macos(10.15));

  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc)
      API_AVAILABLE(macos(10.15));
};

REGISTER(ESProcessEventSubscriber, "event_subscriber", "es_process_events");

Status ESProcessEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_EXEC);
    sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_FORK);
    sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_EXIT);

    subscribe(&ESProcessEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15");
  }
}

Status ESProcessEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  Row r;

  r["pid"] = BIGINT(ec->pid);
  r["path"] = ec->path;
  r["cwd"] = ec->cwd;

  r["parent"] = BIGINT(ec->parent);
  r["original_parent"] = BIGINT(ec->original_parent);

  r["uid"] = BIGINT(ec->uid);
  r["euid"] = BIGINT(ec->euid);
  r["gid"] = BIGINT(ec->gid);
  r["egid"] = BIGINT(ec->egid);

  r["cmdline"] = ec->args;
  r["cmdline_count"] = BIGINT(ec->argc);

  r["env"] = ec->envs;
  r["env_count"] = BIGINT(ec->envc);

  r["signing_id"] = ec->signing_id;
  r["team_id"] = ec->team_id;
  r["cdhash"] = ec->cdhash;

  r["platform_binary"] = (ec->platform_binary) ? INTEGER(1) : INTEGER(0);

  if (ec->event_type == "fork") {
    r["child_pid"] = BIGINT(ec->child_pid);
  }

  if (ec->event_type == "exit") {
    r["exit_code"] = INTEGER(ec->exit_code);
  }

  r["event_type"] = ec->event_type;

  add(r);
  return Status::success();
}
} // namespace osquery
