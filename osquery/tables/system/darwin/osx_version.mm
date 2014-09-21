// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/results.h"

#include <string>

#include <boost/lexical_cast.hpp>

#import "osquery/core/darwin/NSProcessInfo+PECocoaBackports.h"

namespace osquery {
namespace tables {

QueryData genOSXVersion() {
  QueryData results;
  @autoreleasepool {

    NSOperatingSystemVersion v =
        [[NSProcessInfo processInfo] operatingSystemVersion];

    Row r;
    r["major"] = boost::lexical_cast<std::string>(v.majorVersion);
    r["minor"] = boost::lexical_cast<std::string>(v.minorVersion);
    r["patch"] = boost::lexical_cast<std::string>(v.patchVersion);

    results.push_back(r);
  }
  return results;
}
}
}
