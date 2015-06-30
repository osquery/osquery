/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/kernel.h"

#include <osquery/logger.h>

namespace osquery {

class ProcessEventSubscriber
  : public EventSubscriber<KernelEventPublisher> {
 public:
  Status init();

  Status Callback(const TypedKernelEventContextRef<osquery_process_event_t> &ec,
                  const void *user_data);
};

REGISTER(ProcessEventSubscriber, "event_subscriber", "process_events");

Status ProcessEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  sc->event_type = OSQUERY_PROCESS_EVENT;
  LOG(INFO) << "Subscribing to" << sc->event_type;
  subscribe(&ProcessEventSubscriber::Callback, sc, NULL);

  return Status(0, "OK");
}

Status ProcessEventSubscriber::Callback(
    const TypedKernelEventContextRef<osquery_process_event_t> &ec,
    const void *user_data) {
  Row r;
  r["uid"] = BIGINT(ec->event.uid);
  r["euid"] = BIGINT(ec->event.euid);
  r["gid"] = BIGINT(ec->event.gid);
  r["egid"] = BIGINT(ec->event.egid);
  r["owner_uid"] = BIGINT(ec->event.owner_uid);
  r["owner_gid"] = BIGINT(ec->event.owner_gid);
  r["mode"] = BIGINT(ec->event.mode);
  r["path"] = ec->event.path;
  r["time"] = BIGINT(ec->event.time);
  r["uptime"] = BIGINT(ec->event.uptime);

  add(r, ec->time);

  return Status(0, "OK");
}


}  // namespace osquery
