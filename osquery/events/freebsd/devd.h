/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <string>

#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/mutex.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/**
 * @brief Subscription details for DevdEventPublisher.
 *
 * Mirrors the IOKit subscription context shape so the hardware_events table
 * can use either backend with the same call sites.
 */
struct DevdSubscriptionContext : public SubscriptionContext {
  std::string model_id;
  std::string vendor_id;

  /// Bus type, e.g., USB.
  std::string type;
};

/**
 * @brief Event details for DevdEventPublisher.
 *
 * Same shape as IOKitEventContext on Darwin so the hardware_events table
 * subscriber consumes identical fields.
 */
struct DevdEventContext : public EventContext {
  enum Action {
    DEVICE_ATTACH = 0,
    DEVICE_DETACH,
  };

  Action action;
  std::string type;
  std::string vendor;
  std::string model;
  std::string vendor_id;
  std::string model_id;
  std::string path;
  std::string driver;
  std::string version;
  std::string serial;
};

using DevdEventContextRef = std::shared_ptr<DevdEventContext>;
using DevdSubscriptionContextRef = std::shared_ptr<DevdSubscriptionContext>;

/**
 * @brief A FreeBSD devd(8) EventPublisher.
 *
 * Reads from /var/run/devd.seqpacket.pipe, parses notification lines, and
 * fires DEVICE_ATTACH / DEVICE_DETACH events. Publishes under the "iokit"
 * type so subscribers can be shared with the Darwin backend.
 */
class DevdEventPublisher
    : public EventPublisher<DevdSubscriptionContext, DevdEventContext> {
  DECLARE_PUBLISHER("iokit");

 public:
  DevdEventPublisher(const std::string& name = "DevdEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  virtual ~DevdEventPublisher() {
    tearDown();
  }

  Status setUp() override;

  void tearDown() override;

  /// Poll the devd seqpacket socket until interrupted.
  Status run() override;

  bool shouldFire(const DevdSubscriptionContextRef& sc,
                  const DevdEventContextRef& ec) const override;

 private:
  /// Parse a single devd notification line into an event context, fire it.
  void handleLine(const std::string& line);

  /// Devd seqpacket socket file descriptor.
  std::atomic<int> sock_{-1};

  /// Protects sock_ against concurrent close from tearDown.
  mutable Mutex sock_mutex_;
};

} // namespace osquery
