// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include <pwd.h>

#import <Foundation/Foundation.h>

#import <CoreServices/CoreServices.h>
#import <Collaboration/Collaboration.h>

#include "osquery/core.h"
#include "osquery/database/results.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {


QueryData genUsers() {
  QueryData results;

  CSIdentityAuthorityRef defaultAuthority = CSGetLocalIdentityAuthority();

  CSIdentityQueryRef query = CSIdentityQueryCreate(NULL, kCSIdentityClassUser, defaultAuthority);

  CFErrorRef error = NULL;
  CSIdentityQueryExecute(query, 0, &error);

  CFArrayRef users_results = CSIdentityQueryCopyResults(query);
  int numResults = CFArrayGetCount(users_results);

  NSMutableArray * users = [NSMutableArray array];
  for (int i = 0; i < numResults; ++i) {
    CSIdentityRef identity = (CSIdentityRef)CFArrayGetValueAtIndex(users_results, i);
    CBIdentity* identityObject = [CBIdentity identityWithCSIdentity:identity];
    [users addObject:identityObject];
  }
  CFRelease(users_results);
  CFRelease(query);
  CFRelease(defaultAuthority);

  for (CBIdentity* user in users) {
    Row r;

    r["username"] = std::string([[user posixName] UTF8String]);

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


  std::string content;
  Status s = readFile("/etc/passwd", content);
  if (!s.ok()) {
    LOG(ERROR) << "Error reading /etc/passwd: " << s.toString();
  }

  for (const auto& line : split(content, "\n")) {
    auto user_bits = split(line, ":");
    if (user_bits.size() != 7) {
      continue;
    }

    Row r;

    r["username"] = user_bits[0];
    r["uid"] = user_bits[2];
    r["gid"] = user_bits[3];
    r["description"] = user_bits[4];
    r["directory"] = user_bits[5];
    r["shell"] = user_bits[6];

    results.push_back(r);
  }

  return results;
}
}
}
