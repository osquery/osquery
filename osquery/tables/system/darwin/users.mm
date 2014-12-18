/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <pwd.h>

#import <OpenDirectory/OpenDirectory.h>

#include <glog/logging.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

QueryData genUsers(QueryContext &context) {
  @autoreleasepool {
    QueryData results;

    ODSession *session = [ODSession defaultSession];
    NSError *err;
    ODNode *root =
        [ODNode nodeWithSession:session name:@"/Local/Default" error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD node: "
                 << std::string([[err localizedDescription] UTF8String]);
      return results;
    }
    ODQuery *q = [ODQuery queryWithNode:root
                         forRecordTypes:kODRecordTypeUsers
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
      r["username"] = std::string([[re recordName] UTF8String]);
      struct passwd *pwd = nullptr;
      pwd = getpwnam(r["username"].c_str());
      if (pwd != nullptr) {
        r["uid"] = BIGINT(pwd->pw_uid);
        r["gid"] = BIGINT(pwd->pw_gid);
        r["uid_signed"] = BIGINT((int32_t) pwd->pw_uid);
        r["gid_signed"] = BIGINT((int32_t) pwd->pw_gid);
        r["description"] = TEXT(pwd->pw_gecos);
        r["directory"] = TEXT(pwd->pw_dir);
        r["shell"] = TEXT(pwd->pw_shell);
        results.push_back(r);
      }
    }

    return results;
  }
}
}
}
