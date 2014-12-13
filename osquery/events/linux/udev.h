// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <libudev.h>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

enum udev_event_action {
  UDEV_EVENT_ACTION_ADD = 1,
  UDEV_EVENT_ACTION_REMOVE = 2,
  UDEV_EVENT_ACTION_CHANGE = 3,
  UDEV_EVENT_ACTION_UNKNOWN = 4,

  // Custom subscriber-only catch-all for actions.
  UDEV_EVENT_ACTION_ALL = 10,
};

/**
 * @brief Subscriptioning details for UdevEventPublisher events.
 *
 */
struct UdevSubscriptionContext : public SubscriptionContext {
  /// The hardware event action, add/remove/change.
  udev_event_action action;

  /// Restrict to a specific subsystem.
  std::string subsystem;
  /// Restrict to a specific devnode.
  std::string devnode;
  /// Restrict to a specific devtype.
  std::string devtype;
  /// Limit to a specific driver name.
  std::string driver;
};

/**
 * @brief Event details for UdevEventPublisher events.
 */
struct UdevEventContext : public EventContext {
  /// A pointer to the device object, most subscribers will only use device.
  struct udev_device* device;
  /// The udev_event_action identifier.
  udev_event_action action;
  /// Action as a string (as given by udev).
  std::string action_string;

  std::string subsystem;
  std::string devnode;
  std::string devtype;
  std::string driver;
};

typedef std::shared_ptr<UdevEventContext> UdevEventContextRef;
typedef std::shared_ptr<UdevSubscriptionContext> UdevSubscriptionContextRef;

/**
 * @brief A Linux `udev` EventPublisher.
 *
 */
class UdevEventPublisher : public EventPublisher {
  DECLARE_EVENTPUBLISHER(UdevEventPublisher,
                         UdevSubscriptionContext,
                         UdevEventContext);

 public:
  Status setUp();
  void configure();
  void tearDown();

  Status run();

  UdevEventPublisher() : EventPublisher() { handle_ = nullptr; }

  /**
   * @brief Return a string representation of a udev property.
   *
   * @param device the udev device pointer.
   * @param property the udev property identifier string.
   * @return string representation of the property or empty if null.
   */
  static std::string getValue(struct udev_device* device,
                              const std::string& property);

  /**
   * @brief Return a string representation of a udev system attribute.
   *
   * @param device the udev device pointer.
   * @param property the udev system attribute identifier string.
   * @return string representation of the attribute or empty if null.
   */
  static std::string getAttr(struct udev_device* device,
                             const std::string& attr);

 private:
  /// udev handle (socket descriptor contained within).
  struct udev *handle_;
  struct udev_monitor *monitor_;

 private:
  /// Check subscription details.
  bool shouldFire(const UdevSubscriptionContextRef mc,
                  const UdevEventContextRef ec);
  /// Helper function to create an EventContext using a udev_device pointer.
  UdevEventContextRef createEventContext(struct udev_device* device);
};
}
