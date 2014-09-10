// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <stdlib.h>

#include <boost/lexical_cast.hpp>

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include <glog/logging.h>

#include "osquery/core.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery {
namespace tables {

extern std::string safeSecString(const CFStringRef cf_string);

std::string variableFromNumber(const void *value) {
  uint32_t number;
  char number_buffer[10];

  memset(number_buffer, 0, 10);
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

  buffer = (char *)malloc(length * 3 + 1);
  if (buffer == NULL) {
    return "";
  }

  memset(buffer, 0, length * 3 + 1);
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
  nvram_row["name"] = safeSecString((CFStringRef)key);

  // Variable type will be defined by the CF type.
  type_id = CFGetTypeID(value);
  type_description = CFCopyTypeIDDescription(type_id);
  nvram_row["type"] = safeSecString(type_description);
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
    value_string = safeSecString((CFStringRef)value);
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

QueryData genNVRAM() {
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
