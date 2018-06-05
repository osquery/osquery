/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace fs = boost::filesystem;

ssize_t getxattr(const char* path, const char* name, void* value, size_t size) {
  return getxattr(path, name, value, size, 0, 0);
}

ssize_t listxattr(const char* path, char* list, size_t size) {
  return listxattr(path, list, size, 0);
}

int setxattr(const char* path,
             const char* name,
             const void* value,
             size_t size,
             int flags) {
  return setxattr(path, name, value, size, 0, flags);
}

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

Status parseWhereFrom(std::unordered_map<std::string, std::string>& output,
                      const std::string& path) {
  CFStringRef CFPath = CFStringCreateWithCString(
      kCFAllocatorDefault, path.c_str(), kCFStringEncodingUTF8);

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

  CFArrayRef attribs = (CFArrayRef)attributes;
  CFIndex count = CFArrayGetCount(attribs);

  for (CFIndex i = 0; i < count; i++) {
    CFStringRef attribute = (CFStringRef)CFArrayGetValueAtIndex(attribs, i);
    auto where_from_attribute = stringFromCFString(attribute);
    if (!where_from_attribute.empty()) {
      output.insert({"where_from", where_from_attribute});
    }
  }

  CFRelease(attributes);
  return Status(0, "OK");
}

void extractQuarantineProperty(
    std::unordered_map<std::string, std::string>& output,
    const std::string& table_key_name,
    CFTypeRef property,
    const std::string& path) {
  std::string value;
  if (CFGetTypeID(property) == CFStringGetTypeID()) {
    value = stringFromCFString((CFStringRef)property);

  } else if (CFGetTypeID(property) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime((CFDateRef)property) +
                     kCFAbsoluteTimeIntervalSince1970;

    value = INTEGER(std::llround(unix_time));

  } else if (CFGetTypeID(property) == CFURLGetTypeID()) {
    value = stringFromCFString(CFURLGetString((CFURLRef)property));
  }

  output.insert({table_key_name, value});
}

Status parseQuarantineFile(std::unordered_map<std::string, std::string>& output,
                           const std::string& path) {
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, (const UInt8*)path.c_str(), path.length(), false);

  if (url == nullptr) {
    return Status(1,
                  "Unable to fetch quarantine data. Error obtaining CFURLRef "
                  "for the following path: " +
                      path);
  }

  CFTypeRef quarantine_properties = nullptr;

  // This is the non-10.10-symbolic version of kCFURLQuarantinePropertiesKey.
  CFStringRef qp_key = CFSTR("NSURLQuarantinePropertiesKey");
  CFURLCopyResourcePropertyForKey(url, qp_key, &quarantine_properties, nullptr);
  CFRelease(qp_key);

  if (quarantine_properties == nullptr) {
    VLOG(1) << "Error retrieving quarantine properties for " << path;
    CFRelease(url);
    return;
  }

  CFTypeRef property = nullptr;
  for (const auto& kv : kQuarantineKeys) {
    CFStringRef key = CFStringCreateWithCString(
        kCFAllocatorDefault, kv.second.c_str(), kCFStringEncodingUTF8);

    if (key != nullptr) {
      if (CFDictionaryGetValueIfPresent(
              (CFDictionaryRef)quarantine_properties, key, &property)) {
        extractQuarantineProperty(output, kv.first, property, path);
      }

      CFRelease(key);
    }
  }

  CFRelease(quarantine_properties);
  CFRelease(url);

  return Status(0, "OK");
}
} // namespace

Status readSpecialExtendedAttribute(
    std::unordered_map<std::string, std::string>& output,
    const std::string& path,
    const std::string& name) {
  output.clear();

  if (name == kWhereFromXattr) {
    auto status = parseWhereFrom(output, path);
    if (!status.ok()) {
      return status;
    }

  } else if (name == kQuarantineXattr) {
    auto status = parseQuarantineFile(output, path);
    if (!status.ok()) {
      return status;
    }
  }

  return Status(0, "OK");
}
} // namespace osquery
