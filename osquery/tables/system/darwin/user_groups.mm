/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#import <OpenDirectory/OpenDirectory.h>

#include "osquery/tables/system/user_groups.h"

namespace osquery {
namespace tables {

QueryData genUserGroups(QueryContext &context) {
  @autoreleasepool {
    QueryData results;
    struct passwd *pwd = nullptr;

    if (context.constraints["uid"].exists(EQUALS)) {
      std::set<std::string> uids = context.constraints["uid"].getAll(EQUALS);
      for (const auto &uid : uids) {
        pwd = getpwuid(std::strtol(uid.c_str(), NULL, 10));
        if (pwd != nullptr) {
          user_t<int, int> user;
          user.name = pwd->pw_name;
          user.uid = pwd->pw_uid;
          user.gid = pwd->pw_gid;
          getGroupsForUser<int, int>(results, user);
        }
      }
    } else {
        ODSession *session = [ODSession defaultSession];
        NSError *err;
        ODNode *root =
            [ODNode nodeWithSession:session name:@"/Local/Default" error:&err];
        if (err) {
          TLOG << "Error with OD node: "
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
          TLOG << "Error with OD query: "
                     << std::string([[err localizedDescription] UTF8String]);
          return results;
        }

        NSArray *od_results = [q resultsAllowingPartial:NO error:&err];
        if (err) {
          TLOG << "Error with OD results: "
                     << std::string([[err localizedDescription] UTF8String]);
          return results;
        }

        for (ODRecord *re in od_results) {
          std::string username = std::string([[re recordName] UTF8String]);
          struct passwd *pwd = getpwnam(username.c_str());
          if (pwd != nullptr) {
            user_t<int, int> user;
            user.name = pwd->pw_name;
            user.uid = pwd->pw_uid;
            user.gid = pwd->pw_gid;
            getGroupsForUser<int, int>(results, user);
          }
        }
      }

    return results;
  }
}
}
}
