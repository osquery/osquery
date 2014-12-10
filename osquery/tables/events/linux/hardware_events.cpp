// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

/**
 * @brief Track udev events in Linux
 */
class HardwareEventSubscriber : public EventSubscriber {
  DECLARE_EVENTSUBSCRIBER(HardwareEventSubscriber, UdevEventPublisher);
  DECLARE_CALLBACK(Callback, UdevEventContext);

 public:
  void init();

  Status Callback(const UdevEventContextRef ec);
};

REGISTER_EVENTSUBSCRIBER(HardwareEventSubscriber);

void HardwareEventSubscriber::init() {
  auto subscription = UdevEventPublisher::createSubscriptionContext();
  subscription->action = UDEV_EVENT_ACTION_ALL;

  BIND_CALLBACK(Callback, subscription);
}

Status HardwareEventSubscriber::Callback(const UdevEventContextRef ec) {
  Row r;

  if (ec->devtype.empty()) {
    // Superfluous hardware event.
    return Status(0, "Missing type.");
  } else if (ec->devnode.empty() && ec->driver.empty()) {
    return Status(0, "Missing node and driver.");
  }

  struct udev_device *device = ec->device;
  r["action"] = ec->action_string;
  r["path"] = ec->devnode;
  r["type"] = ec->devtype;
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

  r["time"] = INTEGER(ec->time);
  add(r, ec->time);
  return Status(0, "OK");
}
}
}
