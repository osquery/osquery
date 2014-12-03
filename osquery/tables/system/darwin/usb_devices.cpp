// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>

#include <stdio.h>
#include <stdlib.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/hid/IOHIDKeys.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

QueryData genUsbDevices(QueryContext& context) {
  QueryData results;

  io_service_t device;
  char vendor[256];
  char product[256];

  auto matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
  if (matchingDict == nullptr) {
    return results;
  }

  kern_return_t kr;
  io_iterator_t iter;
  kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);

  if (kr != KERN_SUCCESS) {
    return results;
  }

  memset(vendor, 0, 256);
  memset(product, 0, 256);
  while ((device = IOIteratorNext(iter))) {
    Row r;

    // Get the vendor of the device;
    CFMutableDictionaryRef vendor_dict;
    IORegistryEntryCreateCFProperties(
        device, &vendor_dict, kCFAllocatorDefault, kNilOptions);
    CFTypeRef vendor_obj =
        CFDictionaryGetValue(vendor_dict, CFSTR("USB Vendor Name"));
    if (vendor_obj) {
      CFStringRef cf_vendor =
          CFStringCreateCopy(kCFAllocatorDefault, (CFStringRef)vendor_obj);
      CFStringGetCString(cf_vendor, vendor, 255, CFStringGetSystemEncoding());
      r["manufacturer"] = vendor;
      CFRelease(cf_vendor);
    }
    CFRelease(vendor_dict);

    // Get the product name of the device
    CFMutableDictionaryRef product_dict;
    IORegistryEntryCreateCFProperties(
        device, &product_dict, kCFAllocatorDefault, kNilOptions);
    CFTypeRef product_obj =
        CFDictionaryGetValue(product_dict, CFSTR("USB Product Name"));
    if (product_obj) {
      CFStringRef cf_product =
          CFStringCreateCopy(kCFAllocatorDefault, (CFStringRef)product_obj);
      CFStringGetCString(cf_product, product, 255, CFStringGetSystemEncoding());
      r["product"] = product;
      CFRelease(cf_product);
    }
    CFRelease(product_dict);

    // Lets make sure we don't have an empty product & manufacturer
    if (r["product"].size() > 0 || r["manufacturer"].size() > 0) {
      results.push_back(r);
    }

    IOObjectRelease(device);
  }

  IOObjectRelease(iter);
  return results;
}
}
}
