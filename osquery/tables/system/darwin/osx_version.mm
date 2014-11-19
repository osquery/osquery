// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/results.h"

#include <string>

#import "osquery/core/darwin/NSProcessInfo+PECocoaBackports.h"

namespace osquery {
namespace tables {

QueryData genOSXVersion() {
  QueryData results;
  @autoreleasepool {

    NSOperatingSystemVersion v =
        [[NSProcessInfo processInfo] operatingSystemVersion];

    Row r;
    r["major"] = INTEGER(v.majorVersion);
    r["minor"] = INTEGER(v.minorVersion);
    r["patch"] = INTEGER(v.patchVersion);

    results.push_back(r);
  }
  return results;
}
}
}
