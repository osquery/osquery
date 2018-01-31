/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_nvram_defs.hpp>

namespace osquery {
namespace tables {

#define kIODTOptionsPath_ "IODeviceTree:/options"

void genVariable(const void *key, const void *value, void *results) {
  if (key == nullptr || value == nullptr || results == nullptr) {
    // Paranoia: don't expect the callback application to yield nullptrs.
    return;
  }

  // Variable name is the dictionary key.
  Row nvram_row;
  nvram_row["name"] = stringFromCFString((CFStringRef)key);

  // Variable type will be defined by the CF type.
  CFTypeID type_id = CFGetTypeID(value);
  CFStringRef type_description = CFCopyTypeIDDescription(type_id);
  nvram_row["type"] = stringFromCFString(type_description);
  CFRelease(type_description);

  // Based on the type, get a texual representation of the variable.
  std::string value_string;
  if (type_id == CFBooleanGetTypeID()) {
    value_string = (CFBooleanGetValue((CFBooleanRef)value)) ? "true" : "false";
  } else if (type_id == CFNumberGetTypeID()) {
    value_string = stringFromCFNumber((CFDataRef)value);
  } else if (type_id == CFStringGetTypeID()) {
    value_string = stringFromCFString((CFStringRef)value);
  } else if (type_id == CFDataGetTypeID()) {
    value_string = stringFromCFData((CFDataRef)value);
  } else {
    // Unknown result type, do not attempt to decode/format.
    value_string = "<INVALID>";
  }

  // Finally, add the variable value to the row.
  nvram_row["value"] = value_string;
  ((QueryData *)results)->push_back(nvram_row);
}

QueryData genNVRAM(QueryContext &context) {
  QueryData results;

  mach_port_t master_port;
  auto kr = IOMasterPort(bootstrap_port, &master_port);
  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Could not get the IOMaster port";
    return {};
  }

  // NVRAM registry entry is :/options.
  auto options = IORegistryEntryFromPath(master_port, kIODTOptionsPath_);
  if (options == 0) {
    VLOG(1) << "NVRAM is not supported on this system";
    return {};
  }

  CFMutableDictionaryRef options_dict;
  kr = IORegistryEntryCreateCFProperties(options, &options_dict, 0, 0);
  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Could not get NVRAM properties";
  } else {
    CFDictionaryApplyFunction(options_dict, &genVariable, &results);
  }

  // Cleanup (registry entry context).
  CFRelease(options_dict);
  IOObjectRelease(options);
  return results;
}
}
}
