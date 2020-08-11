/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/events/darwin/iokit.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

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

  return Status::success();
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
  add(r);
  return Status::success();
}
}
