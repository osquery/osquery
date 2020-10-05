/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreServices/CoreServices.h>
#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/base64.h>
#include <osquery/utils/chars.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// Structure of any OS X extended attribute
struct XAttrAttribute {
  std::string attribute_data;
  int return_value;
  int buffer_length;
};

const std::string kMetadataXattr = "com.apple.metadata:kMDItemWhereFroms";
const std::string kQuarantineXattr = "com.apple.quarantine";

const std::map<std::string, std::string> kQuarantineKeys = {
    {"quarantine_agent", "LSQuarantineAgentName"},
    {"quarantine_type", "LSQuarantineType"},
    {"quarantine_timestamp", "LSQuarantineTimeStamp"},
    {"quarantine_event_id", "LSQuarantineEventIdentifier"},
    {"quarantine_sender", "LSQuarantineSenderName"},
    {"quarantine_data_url", "LSQuarantineDataURL"},
    {"quarantine_origin_url", "LSQuarantineOriginURL"}};

// Pull the requested extended attribute from the path and return
// the XAttrAttribute structure
struct XAttrAttribute getAttribute(const std::string& path,
                                   const std::string& attribute) {
  struct XAttrAttribute x_att;
  x_att.buffer_length =
      getxattr(path.c_str(), attribute.c_str(), nullptr, (size_t)0, 0, 0);
  char* buffer = (char*)malloc(x_att.buffer_length);
  if (buffer == nullptr) {
    return x_att;
  }

  x_att.return_value = getxattr(
      path.c_str(), attribute.c_str(), buffer, x_att.buffer_length, 0, 0);

  if (x_att.return_value != -1) {
    x_att.attribute_data = std::string(buffer, x_att.buffer_length);
  } else {
    x_att.attribute_data = std::string("");
    x_att.buffer_length = 0;
  }
  free(buffer);
  return x_att;
}

// Pull the list of all the extended attributes for a path
std::vector<std::string> parseExtendedAttributeList(const std::string& path) {
  std::vector<std::string> attributes;
  ssize_t value = listxattr(path.c_str(), nullptr, (size_t)0, 0);
  char* content = (char*)malloc(value);
  if (content == nullptr) {
    return attributes;
  }

  ssize_t ret = listxattr(path.c_str(), content, value, 0);
  if (ret == 0) {
    free(content);
    return attributes;
  }

  char* stable = content;
  do {
    attributes.push_back(std::string(content));
    content += attributes.back().size() + 1;
  } while (content - stable < value);
  free(stable);
  return attributes;
}

void setRow(QueryData& results,
            const std::string& path,
            const std::string& key,
            const std::string& value) {
  Row r;
  r["path"] = path;
  r["directory"] = boost::filesystem::path(path).parent_path().string();
  r["key"] = key;
  auto value_printable = isPrintable(value);
  r["value"] = (value_printable) ? value : base64::encode(value);
  r["base64"] = (value_printable) ? INTEGER(0) : INTEGER(1);
  results.push_back(r);
}

void parseWhereFrom(QueryData& results, const std::string& path) {
  CFStringRef CFPath = CFStringCreateWithCString(
      kCFAllocatorDefault, path.c_str(), kCFStringEncodingUTF8);

  MDItemRef metadata = MDItemCreate(kCFAllocatorDefault, CFPath);
  CFRelease(CFPath);

  if (metadata == nullptr) {
    VLOG(1) << "Metadata for " << path << " is null";
    return;
  }

  CFTypeRef attributes;
  attributes = MDItemCopyAttribute(metadata, kMDItemWhereFroms);
  CFRelease(metadata);

  if (attributes == nullptr) {
    VLOG(1) << "No attributes found for " << path;
    return;
  }

  CFArrayRef attribs = (CFArrayRef)attributes;
  CFIndex count = CFArrayGetCount(attribs);

  for (CFIndex i = 0; i < count; i++) {
    CFStringRef attribute = (CFStringRef)CFArrayGetValueAtIndex(attribs, i);
    auto where_from_attribute = stringFromCFString(attribute);
    if (!where_from_attribute.empty()) {
      setRow(results, path, "where_from", where_from_attribute);
    }
  }

  CFRelease(attributes);
}

void extractQuarantineProperty(const std::string& table_key_name,
                               CFTypeRef property,
                               const std::string& path,
                               QueryData& results) {
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
  setRow(results, path, table_key_name, value);
}

void parseQuarantineFile(QueryData& results, const std::string& path) {
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, (const UInt8*)path.c_str(), path.length(), false);

  if (url == nullptr) {
    VLOG(1) << "Error obtaining CFURLRef for " << path;
    VLOG(1) << "Unable to fetch quarantine data";
    return;
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
        extractQuarantineProperty(kv.first, property, path, results);
      }
      CFRelease(key);
    }
  }

  CFRelease(quarantine_properties);
  CFRelease(url);
}

// Process a file and extract all attribute information, parsed or not.
void getFileData(QueryData& results, const std::string& path) {
  std::vector<std::string> attributes = parseExtendedAttributeList(path);
  for (const auto& attribute : attributes) {
    struct XAttrAttribute x_att = getAttribute(path, attribute);

    if (attribute == kMetadataXattr) {
      parseWhereFrom(results, path);
    } else if (attribute == kQuarantineXattr) {
      parseQuarantineFile(results, path);
    } else {
      setRow(results, path, attribute, x_att.attribute_data);
    }
  }
}

QueryData genXattr(QueryContext& context) {
  QueryData results;
  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    boost::system::error_code ec;
    // Folders can have extended attributes too
    if (!(boost::filesystem::is_regular_file(path, ec) ||
          boost::filesystem::is_directory(path, ec))) {
      continue;
    }
    getFileData(results, path.string());
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directories,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Now loop through constraints using the directory column constraint.
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    std::vector<std::string> files;
    if (listFilesInDirectory(directory_string, files).ok()) {
      for (const auto& file : files) {
        getFileData(results, file);
      }
    }
  }
  return results;
}
}
}
