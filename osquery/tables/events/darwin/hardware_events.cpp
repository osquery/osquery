/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/darwin/iokit.h"

namespace osquery {

/**
 * @brief Track IOKit HID events.
 */
class HardwareEventSubscriber : public EventSubscriber<IOKitEventPublisher> {
 public:
  Status init() override;

  Status Callback(const IOKitEventContextRef& ec,
                  const IOKitSubscriptionContextRef& sc);
};

REGISTER(HardwareEventSubscriber, "event_subscriber", "hardware_events");

Status HardwareEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscribe(&HardwareEventSubscriber::Callback, subscription);

  return Status(0, "OK");
}

Status HardwareEventSubscriber::Callback(
    const IOKitEventContextRef& ec, const IOKitSubscriptionContextRef& sc) {
  Row r;
  if (ec->action == IOKitEventContext::Action::DEVICE_ATTACH) {
    r["action"] = "attach";
  } else {
    r["action"] = "detach";
  }

  r["path"] = ec->path;
  r["type"] = ec->type;
  r["driver"] = ec->driver;

  r["model_id"] = ec->model_id;
  r["model"] = ec->model;
  r["vendor_id"] = ec->vendor_id;
  r["vendor"] = ec->vendor;
  r["serial"] = ec->serial;
  r["revision"] = ec->version;
  add(r, ec->time);
  return Status(0, "OK");
}
}
