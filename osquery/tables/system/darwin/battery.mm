/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#import <IOKit/ps/IOPSKeys.h>
#import <IOKit/ps/IOPowerSources.h>
#import <IOKit/pwr_mgt/IOPM.h>
#import <IOKit/pwr_mgt/IOPMLib.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

NSDictionary* getIopmBatteryInfo() {
  CFTypeRef info = IOPSCopyPowerSourcesInfo();

  if (info == nullptr) {
    return nil;
  }

  CFArrayRef list = IOPSCopyPowerSourcesList(info);
  if (list == nullptr) {
    CFRelease(info);
    return nil;
  }

  CFIndex count = CFArrayGetCount(list);

  // Iterate through power_sources and break at the first internal battery.
  NSDictionary* result = nil;
  for (CFIndex i = 0; i < count; i++) {
    CFTypeRef power_source_handle = CFArrayGetValueAtIndex(list, i);
    CFDictionaryRef power_source_info =
        IOPSGetPowerSourceDescription(info, power_source_handle);
    if (power_source_info) {
      CFStringRef transport_type = (CFStringRef)CFDictionaryGetValue(
          power_source_info, CFSTR(kIOPSTransportTypeKey));
      if (transport_type && CFEqual(transport_type, CFSTR(kIOPSInternalType))) {
        result = (__bridge NSDictionary*)power_source_info;
        break;
      }
    }
  }

  CFRelease(list);
  CFRelease(info);

  return result;
}

NSDictionary* getIopmpsBatteryInfo() {
  CFMutableDictionaryRef matching = IOServiceNameMatching("AppleSmartBattery");
  io_service_t entry =
      IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  matching = nullptr; // Dictionary consumed by IOServiceGetMatchingService
  // From Apple docs:
  // IOService is a subclass of IORegistryEntry, which means any of the
  // IORegistryEntryXXX functions in IOKitLib may be used
  // with io_service_t's as well as io_registry_t's
  CFMutableDictionaryRef properties = nullptr;
  kern_return_t error =
      IORegistryEntryCreateCFProperties(entry, &properties, nullptr, 0);
  IOObjectRelease(entry);

  // dictionary is NULL on kIOReturnInternalError
  if (error != kIOReturnSuccess) {
    return nil;
  }
  return (__bridge_transfer NSDictionary*)properties;
}

BOOL genIopmBatteryInfo(Row& r) {
  NSDictionary* batteryInfo = getIopmBatteryInfo();
  if (batteryInfo == nullptr) {
    return NO;
  }
  if ([batteryInfo objectForKey:@kIOPSHardwareSerialNumberKey]) {
    r["serial_number"] = TEXT([
        [batteryInfo objectForKey:@kIOPSHardwareSerialNumberKey] UTF8String]);
  }
  if ([batteryInfo objectForKey:@kIOPSBatteryHealthKey]) {
    r["health"] =
        TEXT([[batteryInfo objectForKey:@kIOPSBatteryHealthKey] UTF8String]);
  }
  if ([batteryInfo objectForKey:@kIOPSBatteryHealthConditionKey]) {
    r["condition"] = TEXT([[batteryInfo
        objectForKey:@kIOPSBatteryHealthConditionKey] UTF8String]);
  } else {
    r["condition"] = TEXT("Normal");
  }
  if ([batteryInfo objectForKey:@kIOPSPowerSourceStateKey]) {
    r["state"] = TEXT(
        [[batteryInfo objectForKey:@kIOPSPowerSourceStateKey] UTF8String]);
  }
  if ([batteryInfo objectForKey:@kIOPSIsChargingKey]) {
    r["charging"] =
        INTEGER([[batteryInfo objectForKey:@kIOPSIsChargingKey] intValue]);
  }
  if ([batteryInfo objectForKey:@kIOPSIsChargedKey]) {
    r["charged"] = INTEGER(1);
  } else {
    r["charged"] = INTEGER(0);
  }
  if ([batteryInfo objectForKey:@kIOPSCurrentCapacityKey]) {
    r["percent_remaining"] = INTEGER(
        [[batteryInfo objectForKey:@kIOPSCurrentCapacityKey] intValue]);
  }
  if ([batteryInfo objectForKey:@kIOPSTimeToEmptyKey]) {
    r["minutes_until_empty"] =
        INTEGER([[batteryInfo objectForKey:@kIOPSTimeToEmptyKey] intValue]);
  }
  if ([batteryInfo objectForKey:@kIOPSTimeToFullChargeKey]) {
    r["minutes_to_full_charge"] = INTEGER(
        [[batteryInfo objectForKey:@kIOPSTimeToFullChargeKey] intValue]);
  }
  return YES;
}

BOOL genAdvancedBatteryInfo(Row& r) {
  NSDictionary* advancedBatteryInfo = getIopmpsBatteryInfo();
  if (advancedBatteryInfo == nullptr) {
    return NO;
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMPSManufacturerKey]) {
    r["manufacturer"] = TEXT([[advancedBatteryInfo
        objectForKey:@kIOPMPSManufacturerKey] UTF8String]);
  }

  if ([advancedBatteryInfo objectForKey:@kIOPMPSManufactureDateKey]) {
    // Date is published in a bitfield per the Smart Battery Data spec rev 1.1
    // in section 5.1.26 Bits 0...4 => day (value 1-31; 5 bits) Bits 5...8 =>
    // month (value 1-12; 4 bits) Bits 9...15 => years since 1980 (value
    // 0-127; 7 bits)
    int dateMask = [[advancedBatteryInfo
        objectForKey:@kIOPMPSManufactureDateKey] intValue];
    int day = dateMask & 31;
    int month = (dateMask >> 5) & 15;
    int year = (dateMask >> 9) + 1980;

    NSCalendar* calendar = [[NSCalendar alloc]
        initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
    calendar.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    NSDateComponents* components = [[NSDateComponents alloc] init];
    [components setDay:day];
    [components setMonth:month];
    [components setYear:year];
    NSDate* date = [calendar dateFromComponents:components];

    r["manufacture_date"] = INTEGER([date timeIntervalSince1970]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMDeviceNameKey]) {
    r["model"] = TEXT(
        [[advancedBatteryInfo objectForKey:@kIOPMDeviceNameKey] UTF8String]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMPSCycleCountKey]) {
    r["cycle_count"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@kIOPMPSCycleCountKey] intValue]);
  }
  if ([advancedBatteryInfo objectForKey:@"DesignCapacity"]) {
    r["designed_capacity"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@"DesignCapacity"] intValue]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMPSMaxCapacityKey]) {
    r["max_capacity"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@kIOPMPSMaxCapacityKey] intValue]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMPSCurrentCapacityKey]) {
    r["current_capacity"] = INTEGER([[advancedBatteryInfo
        objectForKey:@kIOPMPSCurrentCapacityKey] intValue]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPMPSAmperageKey]) {
    r["amperage"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@kIOPMPSAmperageKey] intValue]);
  }
  if ([advancedBatteryInfo objectForKey:@kIOPSVoltageKey]) {
    r["voltage"] = INTEGER(
        [[advancedBatteryInfo objectForKey:@kIOPSVoltageKey] intValue]);
  }
  return YES;
}

QueryData genBatteryInfo(QueryContext& context) {
  QueryData results;
  Row row;
  @autoreleasepool {
    if (genIopmBatteryInfo(row)){
      genAdvancedBatteryInfo(row);
      results.push_back(row);
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
