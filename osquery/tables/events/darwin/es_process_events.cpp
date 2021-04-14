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
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

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
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

Status ESProcessEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  Row r;

  r["version"] = INTEGER(ec->version);
  r["seq_num"] = BIGINT(ec->seq_num);
  r["global_seq_num"] = BIGINT(ec->global_seq_num);

  r["event_type"] = ec->event_type;

  r["pid"] = BIGINT(ec->pid);
  r["parent"] = BIGINT(ec->parent);
  r["original_parent"] = BIGINT(ec->original_parent);

  r["path"] = ec->path;
  r["cwd"] = ec->cwd;

  r["uid"] = BIGINT(ec->uid);
  r["euid"] = BIGINT(ec->euid);
  r["gid"] = BIGINT(ec->gid);
  r["egid"] = BIGINT(ec->egid);

  r["signing_id"] = ec->signing_id;
  r["team_id"] = ec->team_id;
  r["cdhash"] = ec->cdhash;

  r["cmdline"] = ec->args;
  r["cmdline_count"] = BIGINT(ec->argc);

  r["env"] = ec->envs;
  r["env_count"] = BIGINT(ec->envc);

  r["platform_binary"] = (ec->platform_binary) ? INTEGER(1) : INTEGER(0);

  r["username"] = ec->username;

  if (ec->event_type == "fork") {
    r["child_pid"] = BIGINT(ec->child_pid);
  }

  if (ec->event_type == "exit") {
    r["exit_code"] = INTEGER(ec->exit_code);
  }

  sc->row_list = {r};
  if (!sc->row_list.empty()) {
    addBatch(sc->row_list);
  }

  return Status::success();
}

} // namespace osquery
