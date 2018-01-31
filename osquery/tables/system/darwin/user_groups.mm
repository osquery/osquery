/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#import <OpenDirectory/OpenDirectory.h>
#include <membership.h>

#include "osquery/tables/system/user_groups.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_user_groups_defs.hpp>
#include <generated/tables/tbl_groups_defs.hpp>
#include <generated/tables/tbl_users_defs.hpp>

namespace osquery {
namespace tables {

void genODEntries(ODRecordType type, std::set<std::string> &names) {
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
                         forRecordTypes:type
                              attribute:kODAttributeTypeUniqueID
                              matchType:kODMatchEqualTo
                            queryValues:nil
                       returnAttributes:kODAttributeTypeStandardOnly
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
      names.insert([[re recordName] UTF8String]);
    }
  }
}

QueryData genGroups(QueryContext &context) {
  QueryData results;
  if (context.constraints["gid"].exists(EQUALS)) {
    auto gids = context.constraints["gid"].getAll<long long>(EQUALS);
    for (const auto &gid : gids) {
      Row r;
      struct group *grp = getgrgid(gid);
      r["gid"] = BIGINT(gid);
      if (grp != nullptr) {
        r["groupname"] = std::string(grp->gr_name);
        r["gid_signed"] = BIGINT((int32_t)grp->gr_gid);
      }
      results.push_back(r);
    }
  } else {
    std::set<std::string> groupnames;
    genODEntries(kODRecordTypeGroups, groupnames);
    for (const auto &groupname : groupnames) {
      Row r;
      struct group *grp = getgrnam(groupname.c_str());
      r["groupname"] = groupname;
      if (grp != nullptr) {
        r["gid"] = BIGINT(grp->gr_gid);
        r["gid_signed"] = BIGINT((int32_t)grp->gr_gid);
      }
      results.push_back(r);
    }
  }
  return results;
}

void setRow(Row &r, passwd *pwd) {
  r["gid"] = BIGINT(pwd->pw_gid);
  r["uid_signed"] = BIGINT((int32_t)pwd->pw_uid);
  r["gid_signed"] = BIGINT((int32_t)pwd->pw_gid);
  r["description"] = TEXT(pwd->pw_gecos);
  r["directory"] = TEXT(pwd->pw_dir);
  r["shell"] = TEXT(pwd->pw_shell);

  uuid_t uuid = {0};
  uuid_string_t uuid_string = {0};

  // From the docs: mbr_uid_to_uuid will always succeed and may return a
  // synthesized UUID with the prefix FFFFEEEE-DDDD-CCCC-BBBB-AAAAxxxxxxxx,
  // where 'xxxxxxxx' is a hex conversion of the UID.
  mbr_uid_to_uuid(pwd->pw_uid, uuid);

  uuid_unparse(uuid, uuid_string);
  r["uuid"] = TEXT(uuid_string);
}

QueryData genUsers(QueryContext &context) {
  QueryData results;
  if (context.constraints["uid"].exists(EQUALS)) {
    auto uids = context.constraints["uid"].getAll<long long>(EQUALS);
    for (const auto &uid : uids) {
      struct passwd *pwd = getpwuid(uid);
      if (pwd == nullptr) {
        continue;
      }

      Row r;
      r["uid"] = BIGINT(uid);
      r["username"] = std::string(pwd->pw_name);
      setRow(r, pwd);
      results.push_back(r);
    }
  } else {
    std::set<std::string> usernames;
    genODEntries(kODRecordTypeUsers, usernames);
    for (const auto &username : usernames) {
      struct passwd *pwd = getpwnam(username.c_str());
      if (pwd == nullptr) {
        continue;
      }

      Row r;
      r["uid"] = BIGINT(pwd->pw_uid);
      r["username"] = username;
      setRow(r, pwd);
      results.push_back(r);
    }
  }
  return results;
}

QueryData genUserGroups(QueryContext &context) {
  QueryData results;
  if (context.constraints["uid"].exists(EQUALS)) {
    // Use UID as the index.
    auto uids = context.constraints["uid"].getAll<long long>(EQUALS);
    for (const auto &uid : uids) {
      struct passwd *pwd = getpwuid(uid);
      if (pwd != nullptr) {
        user_t<int, int> user;
        user.name = pwd->pw_name;
        user.uid = pwd->pw_uid;
        user.gid = pwd->pw_gid;
        getGroupsForUser<int, int>(results, user);
      }
    }
  } else {
    std::set<std::string> usernames;
    genODEntries(kODRecordTypeUsers, usernames);
    for (const auto &username : usernames) {
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
