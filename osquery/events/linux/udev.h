/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <libudev.h>

#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/status/status.h>

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
  struct udev_device* device{nullptr};

  /// The udev_event_action identifier.
  udev_event_action action;

  /// Action as a string (as given by udev).
  std::string action_string;

  std::string subsystem;
  std::string devnode;
  std::string devtype;
  std::string driver;
};

using UdevEventContextRef = std::shared_ptr<UdevEventContext>;
using UdevSubscriptionContextRef = std::shared_ptr<UdevSubscriptionContext>;

/**
 * @brief A Linux `udev` EventPublisher.
 *
 */
class UdevEventPublisher
    : public EventPublisher<UdevSubscriptionContext, UdevEventContext> {
  DECLARE_PUBLISHER("udev");

 public:
  virtual ~UdevEventPublisher() {
    tearDown();
  }

  Status setUp() override;

  void tearDown() override;

  Status run() override;

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
  struct udev* handle_{nullptr};

  /// udev monitor.
  struct udev_monitor* monitor_{nullptr};

  /// Protection around udev resources.
  Mutex mutex_;

 private:
  /// Check subscription details.
  bool shouldFire(const UdevSubscriptionContextRef& mc,
                  const UdevEventContextRef& ec) const override;

  /// Helper function to create an EventContext using a udev_device pointer.
  UdevEventContextRef createEventContextFrom(struct udev_device* device);
};
}
