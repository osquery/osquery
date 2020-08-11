/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

FLAG(string,
     hardware_disabled_types,
     "partition",
     "List of disabled hardware event types");

/**
 * @brief Track udev events in Linux
 */
class HardwareEventSubscriber : public EventSubscriber<UdevEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(HardwareEventSubscriber, "event_subscriber", "hardware_events");

Status HardwareEventSubscriber::init() {
  auto subscription = createSubscriptionContext();
  subscription->action = UDEV_EVENT_ACTION_ALL;

  subscribe(&HardwareEventSubscriber::Callback, subscription);
  return Status::success();
}

Status HardwareEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;

  if (ec->devtype.empty()) {
    // Superfluous hardware event.
    return Status::success();
  } else if (ec->devnode.empty() && ec->driver.empty()) {
    return Status::success();
  }

  struct udev_device* device = ec->device;
  r["type"] = ec->devtype;
  if (FLAGS_hardware_disabled_types.find(r.at("type")) != std::string::npos) {
    return Status::success();
  }

  r["action"] = ec->action_string;
  r["path"] = ec->devnode;
  r["driver"] = ec->driver;

  // UDEV properties.
  r["model"] = UdevEventPublisher::getValue(device, "ID_MODEL_FROM_DATABASE");
  if (r["path"].empty() && r["model"].empty()) {
    // Don't emit mising path/model combos.
    return Status::success();
  }

  r["model_id"] = INTEGER(UdevEventPublisher::getValue(device, "ID_MODEL_ID"));
  r["vendor"] = UdevEventPublisher::getValue(device, "ID_VENDOR_FROM_DATABASE");
  r["vendor_id"] =
      INTEGER(UdevEventPublisher::getValue(device, "ID_VENDOR_ID"));
  r["serial"] =
      INTEGER(UdevEventPublisher::getValue(device, "ID_SERIAL_SHORT"));
  r["revision"] = INTEGER(UdevEventPublisher::getValue(device, "ID_REVISION"));
  add(r);
  return Status(0);
}
}
