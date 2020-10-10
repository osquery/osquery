/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <CoreServices/CoreServices.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>

#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/status/status.h>

namespace osquery {

#define kIOPropertyProtocolCharacteristicsKey_ "Protocol Characteristics"
#define kVirtualInterfaceLocation_ "Virtual Interface Location Path"

#define kDAAppearanceTime_ "DAAppearanceTime"

struct DiskArbitrationSubscriptionContext : public SubscriptionContext {
  // Limit events for this subscription to virtual disks (DMG files)
  bool physical_disks{false};
};

struct DiskArbitrationEventContext : public EventContext {
  std::string action;
  std::string path;
  std::string device_path;
  std::string name;
  std::string device;
  std::string uuid;
  std::string size;
  std::string ejectable;
  std::string mountable;
  std::string writable;
  std::string content;
  std::string media_name;
  std::string vendor;
  std::string filesystem;
  std::string disk_appearance_time;
  std::string checksum;
};

using DiskArbitrationEventContextRef =
    std::shared_ptr<DiskArbitrationEventContext>;
using DiskArbitrationSubscriptionContextRef =
    std::shared_ptr<DiskArbitrationSubscriptionContext>;

class DiskArbitrationEventPublisher
    : public EventPublisher<DiskArbitrationSubscriptionContext,
                            DiskArbitrationEventContext> {
  DECLARE_PUBLISHER("diskarbitration");

 public:
  DiskArbitrationEventPublisher(
      const std::string& name = "DiskArbitrationEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  void configure() override {}

  void tearDown() override;

  bool shouldFire(const DiskArbitrationSubscriptionContextRef& sc,
                  const DiskArbitrationEventContextRef& ec) const override;

  Status run() override;

  static void DiskAppearedCallback(DADiskRef disk, void* context);

  static void DiskDisappearedCallback(DADiskRef disk, void* context);

 private:
  void restart();

  void stop() override;

  static std::string getProperty(const CFStringRef& property,
                                 const CFDictionaryRef& dict);

  static std::string extractUdifChecksum(const std::string& path);

  static void fire(const std::string& action,
                   const DiskArbitrationEventContextRef& ec,
                   const CFDictionaryRef& dict);

 private:
  /// Disk arbitration session.
  DASessionRef session_{nullptr};

  /// Publisher's run loop.
  CFRunLoopRef run_loop_{nullptr};

  mutable Mutex mutex_;
};
}
