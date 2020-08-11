/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "plist.h"

#import <Foundation/Foundation.h>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <sstream>

#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/base64.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief Filter selected data types from deserialized property list.
 *
 * Since a property list supports a superset of JSON types we must pass
 * through each type, focusing on the dictionary and list containers, to
 * cherry-pick JSON-supported types. The resultant boost property tree will
 * serialize/deserialize into JSON. It is the most used data type in osquery.
 *
 * The filter functions support:
 * NSString, NSDate, NSNumber, YES, NO, NSArray, and NSDictionary.
 * For NSData the result will be base64 encoded as a string type.
 */
static Status filterDictionary(id plist,
                               const std::string& root,
                               pt::ptree& tree);

/// See filterDictionary, the mimicked logic with a anonymous key more or less.
static Status filterArray(id plist, const std::string& root, pt::ptree& tree);

static inline std::string getValue(id value) {
  if ([value isKindOfClass:[NSString class]]) {
    if ([value UTF8String] != nullptr) {
      return [value UTF8String];
    }
  } else if ([value isKindOfClass:[NSNumber class]]) {
    if ([value stringValue] != nullptr &&
        [[value stringValue] UTF8String] != nullptr) {
      return [[value stringValue] UTF8String];
    }
  } else if ([value isKindOfClass:[NSData class]]) {
    NSString* dataString = [value base64EncodedStringWithOptions:0];
    return [dataString UTF8String];
  } else if ([value isKindOfClass:[NSDate class]]) {
    NSNumber* seconds = [[NSNumber alloc]
        initWithDouble:[value timeIntervalSince1970]];
    return [[seconds stringValue] UTF8String];
  } else if ([value isEqual:@(YES)]) {
    return "true";
  } else if ([value isEqual:@(NO)]) {
    return "false";
  }
  return "";
}

static Status filterDictionary(id plist,
                               const std::string& root,
                               pt::ptree& tree) {
  Status total_status = Status(0, "OK");
  for (id key in [plist allKeys]) {
    if (key == nil || ![key isKindOfClass:[NSString class]]) {
      // Unknown type as dictionary key, most likely a malformed plist.
      continue;
    }

    id value = [plist objectForKey:key];
    if (value == nil) {
      continue;
    }

    auto path_node = std::string([key UTF8String]);
    if ([value isKindOfClass:[NSArray class]]) {
      auto status = filterArray(value, path_node, tree);
      if (!status.ok()) {
        total_status = status;
      }
    } else if ([value isKindOfClass:[NSDictionary class]]) {
      pt::ptree child;
      auto status = filterDictionary(value, "", child);
      if (!status.ok()) {
        total_status = status;
      }
      tree.push_back(pt::ptree::value_type(path_node, std::move(child)));
    } else {
      tree.push_back(
          pt::ptree::value_type(path_node, pt::ptree(getValue(value))));
    }
  }
  return total_status;
}

static Status filterArray(id plist, const std::string& root, pt::ptree& tree) {
  Status total_status = Status(0, "OK");
  pt::ptree child_tree;
  for (id value in plist) {
    if (value == nil) {
      continue;
    }

    pt::ptree child;
    if ([value isKindOfClass:[NSArray class]]) {
      auto status = filterArray(value, "", child);
      if (!status.ok()) {
        total_status = status;
      }
    } else if ([value isKindOfClass:[NSDictionary class]]) {
      auto status = filterDictionary(value, "", child);
      if (!status.ok()) {
        total_status = status;
      }
    } else {
      child.put_value(getValue(value));
    }
    child_tree.push_back(std::make_pair("", std::move(child)));
  }
  tree.push_back(pt::ptree::value_type(root, std::move(child_tree)));
  return total_status;
}

static inline Status filterPlist(NSData* plist, pt::ptree& tree) {
  if ([plist isKindOfClass:[NSDictionary class]]) {
    return filterDictionary((NSMutableDictionary*)plist, "", tree);
  } else if ([plist isKindOfClass:[NSArray class]]) {
    return filterArray((NSMutableArray*)plist, "root", tree);
  } else if ([plist isKindOfClass:[NSData class]]) {
    tree.push_back(pt::ptree::value_type("data", getValue(plist)));
  } else {
    TLOG << "Unknown type during plist filtering: "
         << [[plist className] UTF8String];
    return Status(1, "Unexpected plist type");
  }
  return Status(0, "OK");
}

Status parsePlistContent(const std::string& content, pt::ptree& tree) {
  tree.clear();
  @autoreleasepool {
    id data = [NSData dataWithBytes:content.c_str() length:content.size()];
    if (data == nil) {
      return Status(1, "Unable to create plist content");
    }

    // Read file content into a data object, containing potential plist data.
    NSError* error = nil;
    id plist_data = [NSPropertyListSerialization
        propertyListWithData:data
                     options:NSPropertyListImmutable
                      format:NULL
                       error:&error];
    if (plist_data == nil) {
      std::string error_message([[error localizedFailureReason] UTF8String]);
      VLOG(1) << error_message;
      return Status(1, error_message);
    }
    // Parse the plist data into a core foundation dictionary-literal.
    return filterPlist(plist_data, tree);
  }
}

Status parsePlist(const fs::path& path, pt::ptree& tree) {
  tree.clear();

  auto status = Status();

  @autoreleasepool {
    id ns_path = [NSString stringWithUTF8String:path.string().c_str()];
    id stream = [NSInputStream inputStreamWithFileAtPath:ns_path];
    if (stream == nil) {
      return Status(1, "Unable to read plist: " + path.string());
    }

    // Read file content into a data object, containing potential plist data.
    NSError* error = nil;
    [stream open];
    id plist_data = [NSPropertyListSerialization propertyListWithStream:stream
                                                                options:0
                                                                 format:NULL
                                                                  error:&error];
    if (plist_data == nil) {
      // The most common error is lack of read permissions.
      std::string error_message([[error localizedFailureReason] UTF8String]);
      VLOG(1) << error_message;
      [stream close];
      return Status(1, error_message);
    }

    @try {
      // Parse the plist data into a core foundation dictionary-literal.
      status = filterPlist(plist_data, tree);
    } @catch (NSException* exception) {
      status = Status(1, "Plist data is corrupted");
    }
    [stream close];
  }
  return status;
}

static Status pathFromUnknownAlias(const CFDataRef& data, std::string& result) {
  auto bytes = (const char*)CFDataGetBytePtr(data);
  auto blen = static_cast<size_t>(CFDataGetLength(data));

  size_t off = 0x76;
  while ((off + 4) < blen) {
    size_t rec = (bytes[off] << 8) + bytes[off + 1];
    if (rec == 0xFF) {
      break;
    }

    size_t rsize = (bytes[off + 2] << 8) + bytes[off + 3];
    if (off + 4 + rsize > blen) {
      break;
    }

    if (rec == 0x12) {
      // This is not smart enough to know what mounted device to use.
      result = '/' + std::string(&bytes[off + 4], rsize);
      return Status(0);
    }
    off += 4 + rsize;
  }
  return Status(1, "Cannot find POSIX path tag in Alias");
}

/// Parse a Login Items Plist Alias data for bin path
Status pathFromPlistAliasData(const std::string& data, std::string& result) {
  auto decoded = base64::decode(data);
  if (decoded.size() == 0) {
    // Base64 encoded data (from plist parsing) failed to decode.
    return Status(1, "Failed base64 decode");
  }

  auto alias = CFDataCreate(
      kCFAllocatorDefault, (const UInt8*)decoded.c_str(), decoded.size());
  if (alias == nullptr) {
    // Failed to create CFData object.
    return Status(2, "CFData allocation failed");
  }

  auto bookmark =
      CFURLCreateBookmarkDataFromAliasRecord(kCFAllocatorDefault, alias);
  CFRelease(alias);
  if (bookmark == nullptr) {
    return Status(1, "Alias data is not a bookmark");
  }

  auto url = CFURLCreateByResolvingBookmarkData(
      kCFAllocatorDefault,
      bookmark,
      kCFURLBookmarkResolutionWithoutUIMask |
          kCFURLBookmarkResolutionWithoutMountingMask,
      nullptr,
      nullptr,
      nullptr,
      nullptr);
  if (url != nullptr) {
    // Get the URL-formatted path.
    result = stringFromCFString(CFURLGetString(url));
    if (result.substr(0, 7) == "file://") {
      result = result.substr(7);
    }

    CFRelease(bookmark);
    CFRelease(url);
    return Status(0);
  }

  // Last-ditch effort to parse the Alias record.
  auto status = pathFromUnknownAlias(static_cast<CFDataRef>(bookmark), result);
  CFRelease(bookmark);
  return status;
}

/// Parse a nested (base-64 encoded) plist's alias data for its path
/// Observed experimentally with /Library/Preferences/com.apple.alf.plist
Status pathFromNestedPlistAliasData(const std::string& data,
                                    std::string& result) {
  auto decoded = base64::decode(data);

  if (decoded.size() == 0) {
    return Status(1, "Failed base64 decode");
  }

  pt::ptree plist;
  parsePlistContent(decoded, plist);

  auto nested_data = plist.get<std::string>("data", "");

  return pathFromPlistAliasData(nested_data, result);
}
}
