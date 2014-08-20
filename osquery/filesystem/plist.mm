// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

#import <Foundation/Foundation.h>

using osquery::Status;
namespace pt = boost::property_tree;

namespace osquery {
namespace fs {

NSMutableArray* filterArray(id dataStructure);

NSMutableDictionary* filterDictionary(id dataStructure) {
  NSMutableDictionary* result = [NSMutableDictionary new];
  for (id key in [dataStructure allKeys]) {
    NSString* className =
        NSStringFromClass([[dataStructure objectForKey:key] class]);
    if ([className isEqualToString:@"__NSArrayI"] ||
        [className isEqualToString:@"__NSArrayM"] ||
        [className isEqualToString:@"__NSCFArray"]) {
      [result setObject:filterArray([dataStructure objectForKey:key])
                 forKey:key];
    } else if ([className isEqualToString:@"__NSCFDictionary"]) {
      [result setObject:filterDictionary([dataStructure objectForKey:key])
                 forKey:key];
    } else if ([className isEqualToString:@"__NSCFData"]) {
      [result setObject:@"NSData" forKey:key];
    } else {
      [result setObject:[dataStructure objectForKey:key] forKey:key];
    }
  }
  return result;
}

NSMutableArray* filterArray(id dataStructure) {
  NSMutableArray* result = [NSMutableArray new];
  for (id value in dataStructure) {
    NSString* className = NSStringFromClass([value class]);
    if ([className isEqualToString:@"__NSCFDictionary"]) {
      [result addObject:filterDictionary(value)];
    } else if ([className isEqualToString:@"__NSArrayI"] ||
               [className isEqualToString:@"__NSArrayM"] ||
               [className isEqualToString:@"__NSCFArray"]) {
      [result addObject:filterArray(value)];
    } else if ([className isEqualToString:@"__NSCFData"]) {
      [result addObject:@"NSData"];
    } else {
      [result addObject:value];
    }
  }
  return result;
}

NSMutableDictionary* filterPlist(NSMutableDictionary* plist) {
  return filterDictionary(plist);
}

Status parsePlistContent(const std::string& fileContent, pt::ptree& tree) {
  NSData* plistContent =
      [NSData dataWithBytes:fileContent.c_str() length:fileContent.size()];

  NSError* error;
  NSPropertyListFormat plistFormat;
  NSMutableDictionary* plist = (NSMutableDictionary*)
      [NSPropertyListSerialization propertyListWithData:plistContent
                                                options:NSPropertyListImmutable
                                                 format:&plistFormat
                                                  error:&error];

  if (plist == nil) {
    std::string errorMessage([[error localizedFailureReason] UTF8String]);
    LOG(ERROR) << errorMessage;
    return Status(1, errorMessage);
  } else {
    switch (plistFormat) {
    case NSPropertyListOpenStepFormat:
      VLOG(1) << "plist was in openstep format";
      break;
    case NSPropertyListXMLFormat_v1_0:
      VLOG(1) << "plist was in xml format";
      break;
    case NSPropertyListBinaryFormat_v1_0:
      VLOG(1) << "plist was in binary format";
      break;
    default:
      VLOG(1) << "plist was in unknown format";
      break;
    }
  }

  try {
    plist = filterPlist(plist);
  }
  catch (const std::exception& e) {
    LOG(ERROR)
        << "An exception occured while filtering the plist: " << e.what();
    return Status(1, e.what());
  }

  NSData* jsonDataObjc;
  if ([NSJSONSerialization isValidJSONObject:plist]) {
    jsonDataObjc =
        [NSJSONSerialization dataWithJSONObject:plist options:0 error:&error];
  } else {
    return Status(1, "Valid JSON was not deserialized");
  }
  if (jsonDataObjc == nil) {
    std::string errorMessage([[error localizedFailureReason] UTF8String]);
    LOG(ERROR) << errorMessage;
    return Status(1, errorMessage);
  }

  NSString* jsonStringObjc =
      [[NSString alloc] initWithBytes:[jsonDataObjc bytes]
                               length:[jsonDataObjc length]
                             encoding:NSUTF8StringEncoding];
  std::string jsonStringCxx = std::string([jsonStringObjc UTF8String]);
  VLOG(2) << "Deserialized JSON content from plist: " << jsonStringCxx;
  std::stringstream ss;
  ss << jsonStringCxx;
  try {
    pt::read_json(ss, tree);
  }
  catch (pt::json_parser::json_parser_error& e) {
    LOG(ERROR) << "Error reading JSON: " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

Status parsePlist(const std::string& path, pt::ptree& tree) {
  std::string fileContent;
  Status s = readFile(path, fileContent);
  if (!s.ok()) {
    return s;
  }
  return parsePlistContent(fileContent, tree);
}
}
}
