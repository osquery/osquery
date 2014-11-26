// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <grp.h>

#import <OpenDirectory/OpenDirectory.h>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/filesystem.h"
#include "osquery/tables.h"

namespace osquery {
namespace tables {

QueryData genGroups(QueryContext &context) {
  @autoreleasepool {
    QueryData results;

    ODSession *s = [ODSession defaultSession];
    NSError *err;
    ODNode *root = [ODNode nodeWithSession:s name:@"/Local/Default" error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD node: "
                 << std::string([[err localizedDescription] UTF8String]);
      return results;
    }
    ODQuery *q = [ODQuery queryWithNode:root
                         forRecordTypes:kODRecordTypeGroups
                              attribute:nil
                              matchType:0
                            queryValues:nil
                       returnAttributes:nil
                         maximumResults:0
                                  error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD query: "
                 << std::string([[err localizedDescription] UTF8String]);
      return results;
    }

    NSArray *od_results = [q resultsAllowingPartial:NO error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD results: "
                 << std::string([[err localizedDescription] UTF8String]);
      return results;
    }
    for (ODRecord *re in od_results) {
      Row r;
      r["groupname"] = std::string([[re recordName] UTF8String]);
      struct group *grp = nullptr;
      grp = getgrnam(r["groupname"].c_str());
      if (grp != nullptr) {
        r["gid"] = BIGINT(grp->gr_gid);
        results.push_back(r);
      }
    }

    return results;
  }
}
}
}
