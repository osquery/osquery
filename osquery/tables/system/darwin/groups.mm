// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include <grp.h>

#import <OpenDirectory/OpenDirectory.h>

#include "osquery/core.h"
#include "osquery/database/results.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData genGroups() {
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
      r["name"] = std::string([[re recordName] UTF8String]);
      struct group *grp = nullptr;
      grp = getgrnam(r["name"].c_str());
      if (grp != nullptr) {
        r["gid"] = boost::lexical_cast<std::string>(grp->gr_gid);
        results.push_back(r);
      }
    }

    return results;
  }
}
}
}
