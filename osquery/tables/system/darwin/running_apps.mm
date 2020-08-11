/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genRunningApps(QueryContext& context) {
  QueryData results;
  if (!context.isAnyColumnUsed({"pid", "bundle_identifier", "is_active"})) {
    return results;
  }

  NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
  // If query contains "where is_active = 1", return app in focus without
  // iterating through all apps
  if (context.constraints.count("is_active") > 0 &&
      context.constraints.at("is_active").exists(EQUALS) &&
      context.constraints["is_active"].matches<int>(1)) {
    Row r;
    NSRunningApplication* appInFocus = [workspace frontmostApplication];
    context.setIntegerColumnIfUsed(r, "pid", appInFocus.processIdentifier);
    context.setTextColumnIfUsed(r,
                                "bundle_identifier",
                                appInFocus.bundleIdentifier
                                    ? appInFocus.bundleIdentifier.UTF8String
                                    : "");
    context.setIntegerColumnIfUsed(r, "is_active", 1);
    results.push_back(r);
    return results;
  }

  NSArray* runningApplications = [workspace runningApplications];
  for (NSRunningApplication* app in runningApplications) {
    Row r;
    context.setIntegerColumnIfUsed(r, "pid", app.processIdentifier);
    context.setTextColumnIfUsed(
        r,
        "bundle_identifier",
        app.bundleIdentifier ? app.bundleIdentifier.UTF8String : "");
    context.setIntegerColumnIfUsed(r, "is_active", app.isActive ? 1 : 0);
    results.push_back(r);
  }
  return results;
}

}
}
