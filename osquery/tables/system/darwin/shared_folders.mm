/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#import <OpenDirectory/OpenDirectory.h>

namespace osquery {
namespace tables {

void genSharePointEntries(NSMutableArray *sharepoints) {
  @autoreleasepool {
    ODSession *s = [ODSession defaultSession];
    NSError *err = nullptr;
    ODNode *root = [ODNode nodeWithSession:s name:@"/Local/Default" error:&err];
    if (err != nullptr) {
      TLOG << "Error with OpenDirectory node: "
           << std::string([[err localizedDescription] UTF8String]);
      return;
    }

    ODQuery *q = [ODQuery queryWithNode:root
                         forRecordTypes:kODRecordTypeSharePoints
                              attribute:@"dsAttrTypeNative:directory_path"
                              matchType:kODMatchEqualTo
                            queryValues:nil
                       returnAttributes:kODAttributeTypeNativeOnly
                         maximumResults:0
                                  error:&err];
    if (err != nullptr) {
      TLOG << "Error with OpenDirectory query: "
           << std::string([[err localizedDescription] UTF8String]);
      return;
    }

    // Obtain the results synchronously, not good for very large sets.
    NSArray *od_results = [q resultsAllowingPartial:NO error:&err];
    if (err != nullptr) {
      TLOG << "Error with OpenDirectory results: "
           << std::string([[err localizedDescription] UTF8String]);
      return;
    }

    for (ODRecord *re in od_results) {
      NSDictionary *recordPath = [re recordDetailsForAttributes:nil error:&err];
      if (err != nullptr) {
        TLOG << "Error with OpenDirectory attribute: "
             << std::string([[err localizedDescription] UTF8String]);
        return;
      } else {
        [sharepoints addObject: recordPath];
      }
    }
  }
}

QueryData genSharedFolders(QueryContext &context) {
  NSMutableArray *sharepoints = [[NSMutableArray alloc] init];
  QueryData results;
  genSharePointEntries(sharepoints);
  for (id sharepoint in sharepoints) {
    Row r;
    r["name"] = [[[sharepoint valueForKey:@"dsAttrTypeNative:smb_name"] lastObject] UTF8String];
    r["path"] = [[[sharepoint valueForKey:@"dsAttrTypeNative:directory_path"] lastObject] UTF8String];
    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
