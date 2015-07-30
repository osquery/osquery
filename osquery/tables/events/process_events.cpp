/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/logger.h>

#include "osquery/events/kernel.h"

namespace osquery {

class ProcessEventSubscriber
  : public EventSubscriber<KernelEventPublisher> {
 public:
  /// The process event subscriber declares a kernel event type subscription.
  Status init();

  /// Kernel events matching the event type will fire.
  Status Callback(const TypedKernelEventContextRef<osquery_process_event_t> &ec,
                  const void *user_data);
};

REGISTER(ProcessEventSubscriber, "event_subscriber", "process_events");

Status ProcessEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->event_type = OSQUERY_PROCESS_EVENT;
  sc->udata = nullptr;
  subscribe(&ProcessEventSubscriber::Callback, sc, nullptr);

  return Status(0, "OK");
}

Status ProcessEventSubscriber::Callback(
    const TypedKernelEventContextRef<osquery_process_event_t> &ec,
    const void *user_data) {
  Row r;
  r["overflows"] = "";
  r["cmdline_count"] = BIGINT(ec->event.actual_argc);
  r["cmdline_size"] = BIGINT(ec->event.arg_length);
  if (ec->event.argc != ec->event.actual_argc) {
    r["overflows"] = "cmdline";
  }

  r["envc"] = BIGINT(ec->event.envc);
  r["environment_count"] = BIGINT(ec->event.actual_envc);
  r["environment_size"] = BIGINT(ec->event.env_length);
  if (ec->event.envc != ec->event.actual_envc) {
    r["overflows"] +=
        std::string(((r["overflows"].size() > 0) ? ", " : "")) + "environment";
  }

  char *argv = &(ec->flexible_data.data()[ec->event.argv_offset]);
  std::string argv_accumulator("");
  while (ec->event.argc-- > 0) {
    argv_accumulator += argv;
    argv_accumulator += " ";
    argv += strlen(argv) + 1;
  }
  r["cmdline"] = std::move(argv_accumulator);

  {
    // A configuration can optionally restrict environment variable logging to
    // a whitelist. This is helpful for limiting logged data as well as
    // protecting against logging unsafe/private variables.
    bool use_whitelist = false;
    pt::ptree whitelist;

    // Check if an events whitelist exists.
    ConfigDataInstance config;
    if (config.data().count("events")) {
      // Only apply a whitelist search if the events and environment_variables
      // keys are included. Otherwise, optimize by adding all.
      if (config.data().get_child("events").count("environment_variables")) {
        use_whitelist = true;
        whitelist = config.data().get_child("events.environment_variables");
      }
    }

    char *envv = &(ec->flexible_data.data()[ec->event.envv_offset]);
    std::string envv_accumulator("");
    while (ec->event.envc-- > 0) {
      auto envv_string = std::string(envv);
      if (use_whitelist) {
        for (const auto &item : whitelist) {
          if (envv_string.find(item.second.data()) == 0) {
            envv_accumulator += std::move(envv_string) + ' ';
            break;
          }
        }
      } else {
        envv_accumulator += std::move(envv_string) + ' ';
      }
      envv += strlen(envv) + 1;
    }
    r["environment"] = std::move(envv_accumulator);
  }

  r["pid"] = BIGINT(ec->event.pid);
  r["parent"] = BIGINT(ec->event.ppid);
  r["uid"] = BIGINT(ec->event.uid);
  r["euid"] = BIGINT(ec->event.euid);
  r["gid"] = BIGINT(ec->event.gid);
  r["egid"] = BIGINT(ec->event.egid);
  r["owner_uid"] = BIGINT(ec->event.owner_uid);
  r["owner_gid"] = BIGINT(ec->event.owner_gid);
  r["create_time"] = BIGINT(ec->event.create_time);
  r["access_time"] = BIGINT(ec->event.access_time);
  r["modify_time"] = BIGINT(ec->event.modify_time);
  r["change_time"] = BIGINT(ec->event.change_time);
  r["mode"] = BIGINT(ec->event.mode);
  r["path"] = ec->event.path;
  r["uptime"] = BIGINT(ec->uptime);

  add(r, ec->time);

  return Status(0, "OK");
}


}  // namespace osquery
