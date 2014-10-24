// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include <pwd.h>

#import <OpenDirectory/OpenDirectory.h>

#include "osquery/core.h"
#include "osquery/database/results.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData genUsers() {
  @autoreleasepool {
    QueryData results;

    ODSession *session = [ODSession defaultSession];
    NSError *err;
    ODNode *root = [ODNode nodeWithSession:session
                           name:@"/Local/Default"
                           error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD node: " << std::string([[err localizedDescription] UTF8String]);
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
      LOG(ERROR) << "Error with OD query: " << std::string([[err localizedDescription] UTF8String]);
      return results;
    }

    NSArray *od_results = [q resultsAllowingPartial:NO
                           error:&err];
    if (err) {
      LOG(ERROR) << "Error with OD results: " << std::string([[err localizedDescription] UTF8String]);
      return results;
    }

    for (ODRecord *re in od_results) {
      Row r;
      r["username"] = std::string([[re recordName] UTF8String]);
      struct passwd *pwd = nullptr;
      pwd = getpwnam(r["username"].c_str());
      if (pwd != nullptr) {
        r["uid"] = boost::lexical_cast<std::string>(pwd->pw_uid);
        r["gid"] = boost::lexical_cast<std::string>(pwd->pw_gid);
        r["description"] = std::string(pwd->pw_gecos);
        r["directory"] = std::string(pwd->pw_dir);
        r["shell"] = std::string(pwd->pw_shell);
        results.push_back(r);
      }
    }

    return results;
  }
}
}
}
