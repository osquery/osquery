// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <stdio.h>
#include <stdlib.h>

#include <boost/lexical_cast.hpp>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOKitKeys.h>
#include <CoreFoundation/CoreFoundation.h>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery { namespace tables {

void genVariable(const void *key, const void *value, void *results) {  
  Row nvram_row;

  // Variable type casting members.
  long          cnt, cnt2;
  const uint8_t *dataPtr;
  uint8_t       dataChar;
  char          numberBuffer[10];
  char          *dataBuffer = 0;
  CFIndex       valueLen;
  char          *valueBuffer = 0;
  const char    *valueString = 0;
  uint32_t      number, length;
  // OF variable canonical type casting.
  CFTypeID      typeID;
  CFIndex       typeLen;
  char          *typeBuffer;
  // Get the OF variable's name.
  CFIndex       nameLen;
  char          *nameBuffer = 0;

  nameLen = CFStringGetLength((CFStringRef) key) + 1;
  nameBuffer = (char*) malloc(nameLen);
  if(nameBuffer && CFStringGetCString((CFStringRef) key, nameBuffer, nameLen, 
      kCFStringEncodingUTF8)) {
    nvram_row["name"] = boost::lexical_cast<std::string>(nameBuffer);
  } else {
    LOG(WARNING) << "Unable to convert NVRAM property name to C string";
    goto cleanup;
  }

  // Get the OF variable's type.
  typeID = CFGetTypeID(value);
  typeLen = CFStringGetLength(CFCopyTypeIDDescription(typeID)) + 1;
  typeBuffer = (char*) malloc(typeLen);
  if (typeBuffer && CFStringGetCString(CFCopyTypeIDDescription(typeID), 
      typeBuffer, typeLen, kCFStringEncodingUTF8)) {
    nvram_row["type"] = boost::lexical_cast<std::string>(typeBuffer);
  } else {
    goto cleanup;
  }

  // Based on the type, get a texual representation of the variable.
  if (typeID == CFBooleanGetTypeID()) {
    valueString = (CFBooleanGetValue((CFBooleanRef) value)) ? "true" : "false";
  } else if (typeID == CFNumberGetTypeID()) {
    CFNumberGetValue((CFNumberRef) value, kCFNumberSInt32Type, &number);
    if (number == 0xFFFFFFFF) { 
      sprintf(numberBuffer, "-1"); 
    } else if (number < 1000) { 
      sprintf(numberBuffer, "%d", number); 
    } else { 
      sprintf(numberBuffer, "0x%x", number); 
    }
    valueString = numberBuffer;
  } else if (typeID == CFStringGetTypeID()) {
    valueLen = CFStringGetLength((CFStringRef) value) + 1;
    valueBuffer = (char*) malloc(valueLen);
    if (valueBuffer && CFStringGetCString((CFStringRef) value, valueBuffer, 
        valueLen, kCFStringEncodingUTF8)) {
      valueString = valueBuffer;
    } else {
      LOG(WARNING) << "Unable to convert NVRAM value to C string";
      goto cleanup;
    }
  } else if (typeID == CFDataGetTypeID()) {
    length = CFDataGetLength((CFDataRef) value);
    if (length == 0) {
      valueString = "";
    } else {
      dataBuffer = (char*) malloc(length * 3 + 1);
      if (dataBuffer != 0) {
        dataPtr = CFDataGetBytePtr((CFDataRef) value);
        for (cnt = cnt2 = 0; cnt < length; cnt++) {
          dataChar = dataPtr[cnt];
          if (isprint(dataChar)) {
            dataBuffer[cnt2++] = dataChar;
          } else {
            sprintf(dataBuffer + cnt2, "%%%02x", dataChar);
            cnt2 += 3;
          }
        }
        dataBuffer[cnt2] = '\0';
        valueString = dataBuffer;
      }
    }
  } else {
    valueString = "<INVALID>";
  }

  // Finally, add the variable's value to the row.
  if (valueString != 0) {
    nvram_row["value"] = boost::lexical_cast<std::string>(valueString);
  }
  ((QueryData *) results)->push_back(nvram_row);
  
cleanup:
  if (nameBuffer != 0) {
    free(nameBuffer);
  }
  if (typeBuffer != 0) {
    free(typeBuffer);
  }
  if (dataBuffer != 0) { 
    free(dataBuffer);
  }
  if (valueBuffer != 0) {
    free(valueBuffer);
  }
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
  return results;
}

}}
