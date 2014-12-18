/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#import "osquery/core/darwin/NSProcessInfo+PECocoaBackports.h"

#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genOSXVersion(QueryContext& context) {
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
