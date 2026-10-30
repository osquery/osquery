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

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/base64.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief The most arrays and dictionaries a property list may nest.
 *
 * The filter, and the tables walking its tree, recurse once per level.
 */
const size_t kPlistMaxDepth = 64;

/**
 * @brief The most a property list may grow to as a tree, in bytes.
 *
 * Each value counts its tree node, key and data. A binary plist may reference
 * one object from many places and the tree repeats it each time: N nested
 * arrays of [previous, previous] are 2^N values. The limit stays well under
 * the watchdog's worker memory limit.
 */
const size_t kPlistMaxTreeSize = 16 * 1024 * 1024;

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
 *
 * The walk fails past kPlistMaxDepth or once the tree would exceed its
 * budget, what is left of kPlistMaxTreeSize.
 */
static Status filterDictionary(id plist,
                               const std::string& root,
                               pt::ptree& tree,
                               size_t depth,
                               size_t& budget);

/// See filterDictionary, the mimicked logic with a anonymous key more or less.
static Status filterArray(id plist,
                          const std::string& root,
                          pt::ptree& tree,
                          size_t depth,
                          size_t& budget);

/// Copy a string as UTF-8, "" when it has none (nil, or invalid UTF-16).
static inline std::string stringFromNSString(NSString* value) {
  const char* utf8 = [value UTF8String];
  return (utf8 != nullptr) ? std::string(utf8) : std::string();
}

/// Charge a value's tree node, key and data to the walk's budget.
static inline Status chargeValue(size_t& budget,
                                 size_t key_size,
                                 size_t data_size) {
  auto size = sizeof(pt::ptree::value_type) + key_size + data_size;
  if (size > budget) {
    return Status::failure("Plist expands beyond the size limit");
  }
  budget -= size;
  return Status::success();
}

static inline std::string getValue(id value) {
  if ([value isKindOfClass:[NSString class]]) {
    return stringFromNSString(value);
  } else if ([value isKindOfClass:[NSNumber class]]) {
    return stringFromNSString([value stringValue]);
  } else if ([value isKindOfClass:[NSData class]]) {
    NSString* dataString = [value base64EncodedStringWithOptions:0];
    return stringFromNSString(dataString);
  } else if ([value isKindOfClass:[NSDate class]]) {
    NSNumber* seconds =
        [[NSNumber alloc] initWithDouble:[value timeIntervalSince1970]];
    return stringFromNSString([seconds stringValue]);
  } else if ([value isEqual:@(YES)]) {
    return "true";
  } else if ([value isEqual:@(NO)]) {
    return "false";
  }
  return "";
}

static Status filterDictionary(id plist,
                               const std::string& root,
                               pt::ptree& tree,
                               size_t depth,
                               size_t& budget) {
  if (depth >= kPlistMaxDepth) {
    return Status::failure("Plist nesting exceeds the depth limit");
  }

  for (id key in [plist allKeys]) {
    if (key == nil || ![key isKindOfClass:[NSString class]]) {
      // Unknown type as dictionary key, most likely a malformed plist.
      continue;
    }

    id value = [plist objectForKey:key];
    if (value == nil) {
      continue;
    }

    const char* key_string = [key UTF8String];
    if (key_string == nullptr) {
      // The key has no UTF-8 form (invalid UTF-16), a malformed plist.
      continue;
    }

    auto path_node = std::string(key_string);
    bool is_array = [value isKindOfClass:[NSArray class]];
    bool is_dictionary = [value isKindOfClass:[NSDictionary class]];
    auto data = (is_array || is_dictionary) ? std::string() : getValue(value);
    auto status = chargeValue(budget, path_node.size(), data.size());
    if (!status.ok()) {
      return status;
    }

    if (is_array) {
      status = filterArray(value, path_node, tree, depth + 1, budget);
      if (!status.ok()) {
        return status;
      }
    } else if (is_dictionary) {
      pt::ptree child;
      status = filterDictionary(value, "", child, depth + 1, budget);
      if (!status.ok()) {
        return status;
      }
      tree.push_back(pt::ptree::value_type(path_node, std::move(child)));
    } else {
      tree.push_back(pt::ptree::value_type(path_node, pt::ptree(data)));
    }
  }
  return Status::success();
}

static Status filterArray(id plist,
                          const std::string& root,
                          pt::ptree& tree,
                          size_t depth,
                          size_t& budget) {
  if (depth >= kPlistMaxDepth) {
    return Status::failure("Plist nesting exceeds the depth limit");
  }

  pt::ptree child_tree;
  for (id value in plist) {
    if (value == nil) {
      continue;
    }

    bool is_array = [value isKindOfClass:[NSArray class]];
    bool is_dictionary = [value isKindOfClass:[NSDictionary class]];
    auto data = (is_array || is_dictionary) ? std::string() : getValue(value);
    auto status = chargeValue(budget, 0, data.size());
    if (!status.ok()) {
      return status;
    }

    pt::ptree child;
    if (is_array) {
      status = filterArray(value, "", child, depth + 1, budget);
      if (!status.ok()) {
        return status;
      }
    } else if (is_dictionary) {
      status = filterDictionary(value, "", child, depth + 1, budget);
      if (!status.ok()) {
        return status;
      }
    } else {
      child.put_value(data);
    }
    child_tree.push_back(std::make_pair("", std::move(child)));
  }
  tree.push_back(pt::ptree::value_type(root, std::move(child_tree)));
  return Status::success();
}

static inline Status filterPlist(NSData* plist, pt::ptree& tree) {
  size_t budget = kPlistMaxTreeSize;
  Status status;
  if ([plist isKindOfClass:[NSDictionary class]]) {
    status = filterDictionary((NSMutableDictionary*)plist, "", tree, 0, budget);
  } else if ([plist isKindOfClass:[NSArray class]]) {
    status = filterArray((NSMutableArray*)plist, "root", tree, 0, budget);
  } else if ([plist isKindOfClass:[NSData class]]) {
    tree.push_back(pt::ptree::value_type("data", getValue(plist)));
  } else {
    TLOG << "Unknown type during plist filtering: "
         << stringFromNSString([plist className]);
    return Status(1, "Unexpected plist type");
  }

  if (!status.ok()) {
    // Return nothing of a plist the walk refused.
    tree.clear();
  }
  return status;
}

/// Describe why a property list could not be deserialized.
static std::string plistErrorMessage(NSError* error) {
  // The failure reason is optional; the description falls back to the code.
  auto message = stringFromNSString([error localizedFailureReason]);
  if (message.empty()) {
    message = stringFromNSString([error localizedDescription]);
  }
  return message.empty() ? "Unable to parse plist" : message;
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
      auto error_message = plistErrorMessage(error);
      VLOG(1) << error_message;
      return Status(1, error_message);
    }
    // Parse the plist data into a core foundation dictionary-literal.
    return filterPlist(plist_data, tree);
  }
}

Status parsePlist(const fs::path& path, pt::ptree& tree) {
  tree.clear();

  std::string plist_content;
  auto status = readFile(path.string(), plist_content);

  if (!status.ok()) {
    return Status::failure("Unable to read plist: " + path.string());
  }

  NSData* plist_content_view =
      [NSData dataWithBytesNoCopy:plist_content.data()
                           length:plist_content.length()
                     freeWhenDone:false];

  @autoreleasepool {
    // Read file content into a data object, containing potential plist data.
    NSError* error = nil;
    id plist_data = [NSPropertyListSerialization
        propertyListWithData:plist_content_view
                     options:NSPropertyListImmutable
                      format:NULL
                       error:&error];
    if (plist_data == nil) {
      // The most common error is lack of read permissions.
      auto error_message = plistErrorMessage(error);
      VLOG(1) << error_message;
      return Status(1, error_message);
    }

    @try {
      // Parse the plist data into a core foundation dictionary-literal.
      status = filterPlist(plist_data, tree);
    } @catch (NSException* exception) {
      tree.clear();
      status = Status(1, "Plist data is corrupted");
    }
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

/// Parse plist alias data (bookmark) for bin path
/// Used for firewall exceptions and other plist-based alias data
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
} // namespace osquery
