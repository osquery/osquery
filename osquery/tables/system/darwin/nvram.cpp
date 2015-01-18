/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::string variableFromNumber(const void *value) {
  uint32_t number;
  char number_buffer[10];

  memset(number_buffer, 0, sizeof(number_buffer));
  CFNumberGetValue((CFNumberRef)value, kCFNumberSInt32Type, &number);
  if (number == 0xFFFFFFFF) {
    sprintf(number_buffer, "-1");
  } else if (number < 1000) {
    sprintf(number_buffer, "%d", number);
  } else {
    sprintf(number_buffer, "0x%x", number);
  }

  return std::string(number_buffer);
}

std::string variableFromData(const void *value) {
  std::string variable;

  uint32_t length;
  const uint8_t *data_ptr;
  char *buffer = 0;
  uint32_t count, count2;
  uint8_t byte;

  length = CFDataGetLength((CFDataRef)value);
  if (length == 0) {
    return "";
  }

  size_t buffer_length = length * 3 + 1;
  buffer = (char *)malloc(buffer_length);
  if (buffer == NULL) {
    return "";
  }

  memset(buffer, 0, buffer_length);
  data_ptr = CFDataGetBytePtr((CFDataRef)value);
  for (count = count2 = 0; count < length; count++) {
    byte = data_ptr[count];
    if (isprint(byte)) {
      buffer[count2++] = byte;
    } else {
      sprintf(buffer + count2, "%%%02x", byte);
      count2 += 3;
    }
  }

  // Cleanup
  variable = std::string(buffer);
  free(buffer);

  return variable;
}

void genVariable(const void *key, const void *value, void *results) {
  Row nvram_row;
  std::string value_string;

  // OF variable canonical type casting.
  CFTypeID type_id;
  CFStringRef type_description;

  // Variable name is the dictionary key.
  nvram_row["name"] = stringFromCFString((CFStringRef)key);

  // Variable type will be defined by the CF type.
  type_id = CFGetTypeID(value);
  type_description = CFCopyTypeIDDescription(type_id);
  nvram_row["type"] = stringFromCFString(type_description);
  CFRelease(type_description);

  // Based on the type, get a texual representation of the variable.
  if (type_id == CFBooleanGetTypeID()) {
    // Boolean!
    value_string = (CFBooleanGetValue((CFBooleanRef)value)) ? "true" : "false";
  } else if (type_id == CFNumberGetTypeID()) {
    // Number!
    value_string = variableFromNumber(value);
  } else if (type_id == CFStringGetTypeID()) {
    // CFString!
    value_string = stringFromCFString((CFStringRef)value);
  } else if (type_id == CFDataGetTypeID()) {
    // Binary Data
    value_string = variableFromData(value);
  } else {
    // Who knows?
    value_string = "<INVALID>";
  }

  // Finally, add the variable's value to the row.
  nvram_row["value"] = value_string;
  ((QueryData *)results)->push_back(nvram_row);
}

QueryData genNVRAM(QueryContext &context) {
  QueryData results;

  kern_return_t status;
  mach_port_t master_port;
  io_registry_entry_t options_ref;

  status = IOMasterPort(bootstrap_port, &master_port);
  if (status != KERN_SUCCESS) {
    LOG(ERROR) << "Error getting the IOMaster port";
    return {};
  }

  // NVRAM registry entry is :/options.
  options_ref = IORegistryEntryFromPath(master_port, "IODeviceTree:/options");
  if (options_ref == 0) {
    LOG(ERROR) << "NVRAM is not supported on this system";
    return {};
  }

  CFMutableDictionaryRef options_dict;

  status = IORegistryEntryCreateCFProperties(options_ref, &options_dict, 0, 0);
  if (status != KERN_SUCCESS) {
    LOG(ERROR) << "Error getting the firmware variables";
    goto cleanup;
  }

  CFDictionaryApplyFunction(options_dict, &genVariable, &results);

cleanup:
  // Cleanup (registry entry context).
  IOObjectRelease(options_ref);
  CFRelease(options_dict);
  return results;
}
}
}
