/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>
#include <iomanip>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#include "osquery/core/conversions.h"
#include "osquery/events/darwin/diskarbitration.h"

namespace fs = boost::filesystem;
namespace errc = boost::system::errc;

namespace osquery {

const std::string kIOHIDXClassPath{"IOService:/IOResources/IOHDIXController/"};

REGISTER(DiskArbitrationEventPublisher, "event_publisher", "diskarbitration");

void DiskArbitrationEventPublisher::restart() {
  if (run_loop_ == nullptr) {
    return;
  }

  stop();

  WriteLock lock(mutex_);
  session_ = DASessionCreate(kCFAllocatorDefault);
  DARegisterDiskAppearedCallback(
      session_,
      nullptr,
      DiskArbitrationEventPublisher::DiskAppearedCallback,
      nullptr);
  DARegisterDiskDisappearedCallback(
      session_,
      nullptr,
      DiskArbitrationEventPublisher::DiskDisappearedCallback,
      nullptr);

  DASessionScheduleWithRunLoop(session_, run_loop_, kCFRunLoopDefaultMode);
}

Status DiskArbitrationEventPublisher::run() {
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    restart();
  }

  CFRunLoopRun();
  return Status(0, "OK");
}

void DiskArbitrationEventPublisher::stop() {
  if (run_loop_ == nullptr) {
    return;
  }

  WriteLock lock(mutex_);
  if (session_ != nullptr) {
    DASessionUnscheduleFromRunLoop(session_, run_loop_, kCFRunLoopDefaultMode);
    CFRelease(session_);
    session_ = nullptr;
  }

  CFRunLoopStop(run_loop_);
}

void DiskArbitrationEventPublisher::tearDown() {
  stop();
  run_loop_ = nullptr;
}

void DiskArbitrationEventPublisher::DiskAppearedCallback(DADiskRef disk,
                                                         void* context) {
  auto ec = createEventContext();

  CFDictionaryRef disk_properties = DADiskCopyDescription(disk);
  CFTypeRef devicePathKey;
  if (!CFDictionaryGetValueIfPresent(
          disk_properties, kDADiskDescriptionDevicePathKey, &devicePathKey)) {
    CFRelease(disk_properties);
    return;
  }

  auto device_path = stringFromCFString((CFStringRef)devicePathKey);
  ec->device_path = device_path;

  auto entry =
      IORegistryEntryFromPath(kIOMasterPortDefault, device_path.c_str());
  if (entry == MACH_PORT_NULL) {
    CFRelease(disk_properties);
    return;
  }

  auto protocol_properties = (CFDictionaryRef)IORegistryEntryCreateCFProperty(
      entry,
      CFSTR(kIOPropertyProtocolCharacteristicsKey_),
      kCFAllocatorDefault,
      kNilOptions);

  if (protocol_properties != nullptr) {
    CFDataRef path = (CFDataRef)CFDictionaryGetValue(
        protocol_properties, CFSTR(kVirtualInterfaceLocation_));
    if (path != nullptr) {
      ec->path = stringFromCFData(path);
      // extract checksum once on the whole disk and not for every partition
      if (CFBooleanGetValue((CFBooleanRef)CFDictionaryGetValue(
              disk_properties, kDADiskDescriptionMediaWholeKey))) {
        ec->checksum = extractUdifChecksum(ec->path);
      }
    } else {
      // There was no interface location.
      ec->path = getProperty(kDADiskDescriptionDevicePathKey, disk_properties);
    }
    CFRelease(protocol_properties);
  } else {
    ec->path = "";
  }

  if (ec->path.find("/SSD0@0") == std::string::npos) {
    // This is not an internal SSD.
    fire("add", ec, disk_properties);
  }

  CFRelease(disk_properties);
  IOObjectRelease(entry);
}

void DiskArbitrationEventPublisher::DiskDisappearedCallback(DADiskRef disk,
                                                            void* context) {
  CFDictionaryRef disk_properties = DADiskCopyDescription(disk);
  fire("remove", createEventContext(), disk_properties);
  CFRelease(disk_properties);
}

bool DiskArbitrationEventPublisher::shouldFire(
    const DiskArbitrationSubscriptionContextRef& sc,
    const DiskArbitrationEventContextRef& ec) const {
  // We want events for physical disks as well
  if (sc->physical_disks) {
    return true;
  } else {
    // We 'could' only want only virtual disk (DMG) events
    if (ec->action == "add") {
      // Filter events by matching on Virtual Interface based on IO device path
      // return (boost::starts_with(ec->device_path, kIOHIDXClassPath));
      return true;
    } else {
      return true;
    }
  }
}

std::string DiskArbitrationEventPublisher::extractUdifChecksum(
    const std::string& path_str) {
  fs::path path = path_str;
  if (!pathExists(path).ok() || !isReadable(path).ok()) {
    return "";
  }

  boost::system::error_code ec;
  if (!fs::is_regular_file(path, ec) || ec.value() != errc::success) {
    return "";
  }

  // The koly trailer (footer) is 512 bytes
  // http://newosxbook.com/DMG.html
  if (fs::file_size(path) < 512) {
    return "";
  }

  std::ifstream dmg_file(path_str, std::ios::binary);
  if (dmg_file.is_open()) {
    dmg_file.seekg(-512L, std::ios::end);

    char* buffer = new char[4];
    dmg_file.read(buffer, 4);
    std::string koly_signature;
    koly_signature.assign(buffer, 4);
    delete[] buffer;

    // check for valid signature
    if (koly_signature != "koly") {
      dmg_file.close();
      return "";
    }

    uint32_t checksum_size;
    dmg_file.seekg(-156L, std::ios::end);
    dmg_file.read((char*)&checksum_size, sizeof(checksum_size));
    // checksum_size is in big endian and we need to byte swap
    checksum_size = CFSwapInt32(checksum_size);

    dmg_file.seekg(-152L, std::ios::end); // checksum offset
    unsigned char* u_buffer = new unsigned char[checksum_size];
    dmg_file.read((char*)u_buffer, checksum_size);
    // we don't want to byte swap checksum as disk utility/hdiutil doesn't
    std::stringstream checksum;
    for (size_t i = 0; i < checksum_size; i++) {
      if (u_buffer[i] != 0) {
        checksum << std::setw(2) << std::hex << std::uppercase
                 << (unsigned int)u_buffer[i];
      }
    }
    delete[] u_buffer;
    dmg_file.close();
    return checksum.str();
  }
  return "";
}

void DiskArbitrationEventPublisher::fire(
    const std::string& action,
    const DiskArbitrationEventContextRef& ec,
    const CFDictionaryRef& dict) {
  ec->action = action;
  ec->name = getProperty(kDADiskDescriptionMediaNameKey, dict);
  ec->device = "/dev/" + getProperty(kDADiskDescriptionMediaBSDNameKey, dict);
  ec->uuid = getProperty(kDADiskDescriptionVolumeUUIDKey, dict);
  ec->size = getProperty(kDADiskDescriptionMediaSizeKey, dict);
  ec->ejectable = getProperty(kDADiskDescriptionMediaRemovableKey, dict);
  ec->mountable = getProperty(kDADiskDescriptionVolumeMountableKey, dict);
  ec->writable = getProperty(kDADiskDescriptionMediaWritableKey, dict);
  ec->content = getProperty(kDADiskDescriptionMediaContentKey, dict);
  ec->media_name = getProperty(kDADiskDescriptionMediaNameKey, dict);
  ec->vendor = getProperty(kDADiskDescriptionDeviceVendorKey, dict);
  ec->filesystem = getProperty(kDADiskDescriptionVolumeKindKey, dict);
  ec->disk_appearance_time = getProperty(CFSTR(kDAAppearanceTime_), dict);
  if (ec->path.find("IOService:/") == 0) {
    ec->path = ec->device;
  }

  EventFactory::fire<DiskArbitrationEventPublisher>(ec);
}

std::string DiskArbitrationEventPublisher::getProperty(
    const CFStringRef& property, const CFDictionaryRef& dict) {
  CFTypeRef value = (CFTypeRef)CFDictionaryGetValue(dict, property);
  if (value == nullptr) {
    return "";
  }

  if (CFStringCompare(property, CFSTR(kDAAppearanceTime_), kNilOptions) ==
      kCFCompareEqualTo) {
    return stringFromCFAbsoluteTime((CFDataRef)value);
  }

  if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    return stringFromCFNumber((CFDataRef)value,
                              CFNumberGetType((CFNumberRef)value));
  } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
    return stringFromCFString((CFStringRef)value);
  } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
    return (CFBooleanGetValue((CFBooleanRef)value)) ? "1" : "0";
  } else if (CFGetTypeID(value) == CFUUIDGetTypeID()) {
    return stringFromCFString(
        CFUUIDCreateString(kCFAllocatorDefault, (CFUUIDRef)value));
  }
  return "";
}
}
