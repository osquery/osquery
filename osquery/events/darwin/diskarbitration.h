/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>
#include <DiskArbitration/DiskArbitration.h>

#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/make_shared.hpp>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

#define kIOPropertyProtocolCharacteristicsKey_ "Protocol Characteristics"
#define kVirtualInterfaceLocation_ "Virtual Interface Location Path"

#define kDAAppearanceTime_ "DAAppearanceTime"

const std::string kIOHIDXClassPath_ =
    "IOService:/IOResources/IOHDIXController/";

struct DiskArbitrationSubscriptionContext : public SubscriptionContext {
  // Limit events for this subscription to virtual disks (DMG files)
  bool physical_disks;

  DiskArbitrationSubscriptionContext() : physical_disks(false) {}
};

struct DiskArbitrationEventContext : public EventContext {
  std::string action;
  std::string path;
  std::string device_path;
  std::string name;
  std::string bsd_name;
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

typedef std::shared_ptr<DiskArbitrationEventContext>
    DiskArbitrationEventContextRef;
typedef std::shared_ptr<DiskArbitrationSubscriptionContext>
    DiskArbitrationSubscriptionContextRef;

class DiskArbitrationEventPublisher
    : public EventPublisher<DiskArbitrationSubscriptionContext,
                            DiskArbitrationEventContext> {
  DECLARE_PUBLISHER("diskarbitration");

 public:
  void configure() {}
  void tearDown();

  bool shouldFire(const DiskArbitrationSubscriptionContextRef &sc,
                  const DiskArbitrationEventContextRef &ec) const;
  Status run();

  // Callin for stopping the streams/run loop.
  void end() { stop(); }

  static void DiskAppearedCallback(DADiskRef disk, void *context);
  static void DiskDisappearedCallback(DADiskRef disk, void *context);

 private:
  void restart();
  void stop();
  static std::string getProperty(const CFStringRef &property,
                                 const CFDictionaryRef &dict);
  static std::string extractUdifChecksum(const std::string &path);
  static void fire(const std::string &action,
                   const DiskArbitrationEventContextRef &ec,
                   const CFDictionaryRef &dict);

 private:
  DASessionRef session_{nullptr};
  CFRunLoopRef run_loop_{nullptr};
};
}
