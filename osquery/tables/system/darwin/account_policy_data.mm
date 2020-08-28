/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/darwin/plist.h>

#import <OpenDirectory/OpenDirectory.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

void genAccountPolicyDataRow(const std::string& uid, Row& r) {
  ODSession* s = [ODSession defaultSession];
  NSError* err = nullptr;
  ODNode* root = [ODNode nodeWithSession:s name:@"/Local/Default" error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory node: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  ODQuery* q =
      [ODQuery queryWithNode:root
              forRecordTypes:kODRecordTypeUsers
                   attribute:kODAttributeTypeUniqueID
                   matchType:kODMatchEqualTo
                 queryValues:[NSString stringWithFormat:@"%s", uid.c_str()]
            returnAttributes:@"dsAttrTypeNative:accountPolicyData"
              maximumResults:0
                       error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory query: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  // Obtain the results synchronously, not good for very large sets.
  NSArray* od_results = [q resultsAllowingPartial:NO error:&err];
  if (err != nullptr) {
    TLOG << "Error with OpenDirectory results: "
         << std::string([[err localizedDescription] UTF8String]);
    return;
  }

  pt::ptree tree;

  for (ODRecord* re in od_results) {
    NSError* attrErr = nullptr;

    NSArray* userPolicyDataValues =
        [re valuesForAttribute:@"dsAttrTypeNative:accountPolicyData"
                         error:&attrErr];

    if (err != nullptr) {
      TLOG << "Error with OpenDirectory attribute data: "
           << std::string([[attrErr localizedDescription] UTF8String]);
      return;
    }

    if (![userPolicyDataValues count]) {
      return;
    }

    std::string userPlistString =
        [[[NSString alloc] initWithData:userPolicyDataValues[0]
                               encoding:NSUTF8StringEncoding] UTF8String];

    if (userPlistString.empty()) {
      return;
    }

    if (!osquery::parsePlistContent(userPlistString, tree).ok()) {
      TLOG << "Error parsing Account Policy data plist";
      return;
    }
  }

  r["uid"] = BIGINT(uid);
  r["creation_time"] = DOUBLE(tree.get("creationTime", ""));
  r["failed_login_count"] = BIGINT(tree.get("failedLoginCount", ""));
  r["failed_login_timestamp"] = DOUBLE(tree.get("failedLoginTimestamp", ""));
  r["password_last_set_time"] = DOUBLE(tree.get("passwordLastSetTime", ""));
}

QueryData genAccountPolicyData(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = SQL::selectAllFrom("users");
  @autoreleasepool {
    for (const auto& user : users) {
      Row r;
      auto uid = user.at("uid");

      genAccountPolicyDataRow(uid, r);

      // A blank UID implies no policy exists for the user, or the policy is
      // corrupted. We should only return rows where we successfully read an
      // account policy.
      if (r["uid"] != "") {
        results.push_back(r);
      }
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
