/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {
namespace tables {

const std::string kIODTOptionsPath = "IODeviceTree:/options";

Status stringFromNVRAM(const void* value,
                       std::string& type_name,
                       std::string& output) {
  // Variable type will be defined by the CF type.
  CFTypeID type_id = CFGetTypeID(value);
  CFStringRef type_description = CFCopyTypeIDDescription(type_id);
  type_name = stringFromCFString(type_description);

  CFRelease(type_description);

  // Based on the type, get a texual representation of the variable.
  if (type_id == CFBooleanGetTypeID()) {
    output = (CFBooleanGetValue((CFBooleanRef)value)) ? "true" : "false";
  } else if (type_id == CFNumberGetTypeID()) {
    output = stringFromCFNumber((CFDataRef)value);
  } else if (type_id == CFStringGetTypeID()) {
    output = stringFromCFString((CFStringRef)value);
  } else if (type_id == CFDataGetTypeID()) {
    output = stringFromCFData((CFDataRef)value);
  } else {
    // Unknown result type, do not attempt to decode/format.
    return Status::failure("Unknown variable type");
  }
  return Status::success();
}

void genVariable(const void* key, const void* value, void* results) {
  if (key == nullptr || value == nullptr || results == nullptr) {
    // Paranoia: don't expect the callback application to yield nullptrs.
    return;
  }

  // Variable name is the dictionary key.
  Row r;
  auto name = stringFromCFString((CFStringRef)key);

  std::string type_name;
  std::string value_string;
  auto status = stringFromNVRAM(value, type_name, value_string);
  if (!status.ok()) {
    VLOG(1) << "Failed to convert NVRAM variable: " << name;
  } else {
    r["value"] = std::move(value_string);
  }

  r["name"] = std::move(name);
  r["type"] = std::move(type_name);
  ((QueryData*)results)->push_back(r);
}

void genSingleVariable(const io_registry_entry_t& options,
                       const std::string& key,
                       QueryData& results) {
  auto name = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  if (name == nullptr) {
    VLOG(1) << "Cannot create CFString for NVRAM name";
    return;
  }

  auto value =
      IORegistryEntryCreateCFProperty(options, name, kCFAllocatorDefault, 0);
  CFRelease(name);
  if (value == nullptr) {
    LOG(INFO) << "Cannot find NVRAM variable: " << key;
    return;
  }

  Row r;
  std::string type_name;
  std::string value_string;
  auto status = stringFromNVRAM(value, type_name, value_string);
  CFRelease(value);

  if (!status.ok()) {
    VLOG(1) << "Failed to convert NVRAM variable: " << key;
  } else {
    r["value"] = std::move(value_string);
  }

  r["name"] = key;
  r["type"] = std::move(type_name);
  results.push_back(r);
}

QueryData genNVRAM(QueryContext& context) {
  mach_port_t master_port;
  auto kr = IOMasterPort(bootstrap_port, &master_port);
  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Could not get the IOMaster port";
    return {};
  }

  // NVRAM registry entry is :/options.
  auto options = IORegistryEntryFromPath(master_port, kIODTOptionsPath.c_str());
  if (options == MACH_PORT_NULL) {
    VLOG(1) << "NVRAM is not supported on this system";
    return {};
  }

  QueryData results;
  // If the query is requesting an SMC key by name within the predicate.
  if (context.hasConstraint("name", EQUALS)) {
    context.iteritems(
        "name", EQUALS, ([&options, &results](const std::string& key) {
          genSingleVariable(options, key, results);
        }));
  } else {
    CFMutableDictionaryRef options_dict;
    kr = IORegistryEntryCreateCFProperties(
        options, &options_dict, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS) {
      VLOG(1) << "Could not get NVRAM properties";
    } else {
      CFDictionaryApplyFunction(options_dict, &genVariable, &results);
    }

    // Cleanup (registry entry context).
    CFRelease(options_dict);
  }

  IOObjectRelease(options);
  return results;
}
}
}
