/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/registry_factory.h>

#include "osquery/events/linux/udev.h"

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
  return Status(0, "OK");
}

Status HardwareEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;

  if (ec->devtype.empty()) {
    // Superfluous hardware event.
    return Status(0, "Missing type.");
  } else if (ec->devnode.empty() && ec->driver.empty()) {
    return Status(0, "Missing node and driver.");
  }

  struct udev_device* device = ec->device;
  r["type"] = ec->devtype;
  if (FLAGS_hardware_disabled_types.find(r.at("type")) != std::string::npos) {
    return Status(0, "Disabled type.");
  }

  r["action"] = ec->action_string;
  r["path"] = ec->devnode;
  r["driver"] = ec->driver;

  // UDEV properties.
  r["model"] = UdevEventPublisher::getValue(device, "ID_MODEL_FROM_DATABASE");
  if (r["path"].empty() && r["model"].empty()) {
    // Don't emit mising path/model combos.
    return Status(0, "Missing path and model.");
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
