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

#include "osquery/events/darwin/iokit_hid.h"

namespace osquery {
namespace tables {

/**
 * @brief Track IOKit HID events.
 */
class HardwareEventSubscriber : public EventSubscriber<IOKitHIDEventPublisher> {
 public:
  Status init();

  Status Callback(const IOKitHIDEventContextRef& ec, const void* user_data);
};

REGISTER(HardwareEventSubscriber, "event_subscriber", "hardware_events");

Status HardwareEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  // We don't want hardware value changes.
  subscription->values = false;

  subscribe(&HardwareEventSubscriber::Callback, subscription, nullptr);

  return Status(0, "OK");
}

Status HardwareEventSubscriber::Callback(const IOKitHIDEventContextRef& ec,
                                         const void* user_data) {
  Row r;

  r["action"] = ec->action;
  // There is no path in IOKit, there's a location ID (may be useful).
  r["path"] = ec->location;

  // Type and driver are the name in IOKit
  r["type"] = "hid";
  r["driver"] = ec->transport;

  r["model_id"] = ec->model_id;
  r["model"] = ec->model;
  r["vendor_id"] = ec->vendor_id;
  r["vendor"] = ec->vendor;
  r["serial"] = ec->serial; // Not always filled in.
  r["revision"] = ec->version;

  r["time"] = INTEGER(ec->time);
  add(r, ec->time);
  return Status(0, "OK");
}
}
}
