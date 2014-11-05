// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

QueryData genUsb() {
  QueryData results;

    CFMutableDictionaryRef matchingDict;
    io_iterator_t iter;
    kern_return_t kr;
    io_service_t device;
    char vendor[256];
    char product[256];

    matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
    if (matchingDict == NULL)
    { return results; }

    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
    if (kr != KERN_SUCCESS)
    {  return results; }

    while ((device = IOIteratorNext(iter)))
    {
        Row r

        //Get the vendor of the device;
        CFMutableDictionaryRef vendor_dict = NULL;
        IORegistryEntryCreateCFProperties(device, &vendor_dict, kCFAllocatorDefault, kNilOptions);
        CFTypeRef vendor_obj = CFDictionaryGetValue(vendor_dict, CFSTR("USB Vendor Name"));
        if(vendor_obj) {
           CFStringRef cf_vendor  =  CFStringCreateCopy(kCFAllocatorDefault, (CFStringRef)vendor_obj);
           CFStringGetCString(cf_vendor, vendor, 256, CFStringGetSystemEncoding());
           r["manufacturer"] = vendor;
        }

        //Get the product name of the device
        CFMutableDictionaryRef product_dict = NULL;
        IORegistryEntryCreateCFProperties(device, &product_dict, kCFAllocatorDefault, kNilOptions);
        CFTypeRef product_obj = CFDictionaryGetValue(product_dict, CFSTR("USB Product Name"));
        if(product_obj) {
           CFStringRef cf_product  =  CFStringCreateCopy(kCFAllocatorDefault, (CFStringRef)product_obj);
           CFStringGetCString(cf_product, product, 256, CFStringGetSystemEncoding());
           r["product"] = product;
        }

         //Lets make sure we don't have an empty product & manufacturer
        if(r["product"] != "" || r["manufacturer"] != "") {
          results.push_back(r);
        }

        IOObjectRelease(device);
    }

  IOObjectRelease(iter);
  return results;
}
}
}
