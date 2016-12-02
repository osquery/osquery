/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#import <Foundation/Foundation.h>

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

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
    NSNumber* seconds =
        [[NSNumber alloc] initWithDouble:[value timeIntervalSince1970]];
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
  } else {
    return filterArray((NSMutableArray*)plist, "root", tree);
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
  // Drop privileges, if needed, before parsing plist data.
  auto dropper = DropPrivileges::get();
  dropper->dropToParent(path);

  auto status = readFile(path);
  if (!status.ok()) {
    return status;
  }

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
    } @catch (NSException* e) {
      LOG(WARNING) << "Plist data is corrupted";
      status = Status(1, "Plist data is corrupted");
    }
    [stream close];
  }
  return status;
}
}
