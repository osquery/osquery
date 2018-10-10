/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <errno.h>
#include <map>

#include <CoreServices/CoreServices.h>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/darwin/special_xattr_decoder.h"

namespace osquery {
namespace {
const std::string kWhereFromXattr = "com.apple.metadata:kMDItemWhereFroms";
const std::string kQuarantineXattr = "com.apple.quarantine";

const std::map<std::string, std::string> kQuarantineKeys = {
    {"quarantine_agent", "LSQuarantineAgentName"},
    {"quarantine_type", "LSQuarantineType"},
    {"quarantine_timestamp", "LSQuarantineTimeStamp"},
    {"quarantine_event_id", "LSQuarantineEventIdentifier"},
    {"quarantine_sender", "LSQuarantineSenderName"},
    {"quarantine_data_url", "LSQuarantineDataURL"},
    {"quarantine_origin_url", "LSQuarantineOriginURL"}};

Status parseWhereFrom(ExtendedAttributes& output, const std::string& path) {
  CFStringRef CFPath = CFStringCreateWithCString(
      kCFAllocatorDefault, path.c_str(), kCFStringEncodingUTF8);

  if (CFPath == nullptr) {
    return Status(
        1,
        "Failed to create the CFString object from the following path: " +
            path);
  }

  MDItemRef metadata = MDItemCreate(kCFAllocatorDefault, CFPath);
  CFRelease(CFPath);

  if (metadata == nullptr) {
    return Status(1, "The metadata for the following path is NULL: " + path);
  }

  CFTypeRef attributes;
  attributes = MDItemCopyAttribute(metadata, kMDItemWhereFroms);
  CFRelease(metadata);

  if (attributes == nullptr) {
    return Status(1, "No attributes found for the following path: " + path);
  }

  auto attribs = static_cast<CFArrayRef>(attributes);
  CFIndex count = CFArrayGetCount(attribs);

  for (CFIndex i = 0; i < count; i++) {
    auto attribute =
        static_cast<CFStringRef>(CFArrayGetValueAtIndex(attribs, i));
    auto where_from_attribute = stringFromCFString(attribute);
    if (!where_from_attribute.empty()) {
      output.push_back(std::make_pair("where_from", where_from_attribute));
    }
  }

  CFRelease(attributes);
  return Status(0);
}

void extractQuarantineProperty(ExtendedAttributes& output,
                               const std::string& table_key_name,
                               CFTypeRef property,
                               const std::string& path) {
  std::string value;
  if (CFGetTypeID(property) == CFStringGetTypeID()) {
    value = stringFromCFString(static_cast<CFStringRef>(property));

  } else if (CFGetTypeID(property) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime((CFDateRef)property) +
                     kCFAbsoluteTimeIntervalSince1970;

    value = INTEGER(std::llround(unix_time));

  } else if (CFGetTypeID(property) == CFURLGetTypeID()) {
    value = stringFromCFString(CFURLGetString(static_cast<CFURLRef>(property)));
  }

  output.push_back(std::make_pair(table_key_name, value));
}

Status parseQuarantineFile(ExtendedAttributes& output,
                           const std::string& path) {
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault,
      reinterpret_cast<const UInt8*>(path.c_str()),
      path.length(),
      false);

  if (url == nullptr) {
    return Status(1,
                  "Unable to fetch quarantine data. Error obtaining CFURLRef "
                  "for the following path: " +
                      path);
  }

  CFTypeRef quarantine_properties = nullptr;

  // This is the non-10.10-symbolic version of kCFURLQuarantinePropertiesKey.
  CFStringRef qp_key = CFSTR("NSURLQuarantinePropertiesKey");
  if (qp_key == nullptr) {
    return Status(1,
                  "Failed to allocate the CFString object for "
                  "kCFURLQuarantinePropertiesKey");
  }

  CFURLCopyResourcePropertyForKey(url, qp_key, &quarantine_properties, nullptr);
  CFRelease(qp_key);

  if (quarantine_properties == nullptr) {
    CFRelease(url);
    return Status(
        1,
        "Error retrieving quarantine properties for the following path: " +
            path);
  }

  CFTypeRef property = nullptr;
  for (const auto& kv : kQuarantineKeys) {
    CFStringRef key = CFStringCreateWithCString(
        kCFAllocatorDefault, kv.second.c_str(), kCFStringEncodingUTF8);

    if (key != nullptr) {
      if (CFDictionaryGetValueIfPresent(
              static_cast<CFDictionaryRef>(quarantine_properties),
              key,
              &property)) {
        extractQuarantineProperty(output, kv.first, property, path);
      }

      CFRelease(key);
    }
  }

  CFRelease(quarantine_properties);
  CFRelease(url);

  return Status(0);
}
} // namespace

bool isSpecialExtendedAttribute(const std::string& name) {
  return (name == kWhereFromXattr || name == kQuarantineXattr);
}

Status decodeSpecialExtendedAttribute(ExtendedAttributes& output,
                                      const std::string& path,
                                      const std::string& name) {
  output.clear();

  Status status;

  if (name == kWhereFromXattr) {
    status = parseWhereFrom(output, path);
  } else if (name == kQuarantineXattr) {
    status = parseQuarantineFile(output, path);
  } else {
    status = Status(1, "Invalid special attribute name");
  }

  return status;
}
} // namespace osquery
