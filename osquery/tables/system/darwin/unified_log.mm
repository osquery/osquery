/**
 * Copyright (c) 2021-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <OSLog/OSLog.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {
    
void genUnifiedLog(QueryData &results) {

    if (@available(macOS 10.15, *)) {
    NSError *error = nil;
    OSLogStore *logstore = [OSLogStore localStoreAndReturnError:&error];
    if (error != nil) {
        NSLog(@"error getting handle to log store: %@", error);
        return;
    }

    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SS"];


    NSDate *interval = [NSDate dateWithTimeIntervalSinceNow:-10];
    OSLogEnumeratorOptions option = 0;
    OSLogPosition *position = [logstore positionWithDate:interval];
    OSLogEnumerator *enumerator = [logstore entriesEnumeratorWithOptions:option
                                                                position:position
                                                               predicate:nil 
                                                                   error:&error];
    if (error != nil) {
        NSLog(@"error enumerating entries in system log: %@", error);
        return;
    }
    for (OSLogEntryLog *entry in enumerator) {
        Row r;
        NSString *dateString = [dateFormatter stringFromDate:[entry date]];
        r["date"] = TEXT([dateString UTF8String]);
        r["message"] = TEXT([[entry composedMessage] UTF8String]);
        r["storage"] = INTEGER([entry storeCategory]);
        if ([entry respondsToSelector:@selector(activityIdentifier)]) {
          r["activity"] = INTEGER([entry activityIdentifier]);
          r["process"] = TEXT([[entry process] UTF8String]);
          r["pid"] = INTEGER([entry processIdentifier]);
          r["sender"] = TEXT([[entry sender] UTF8String]);
          r["tid"] = INTEGER([entry threadIdentifier]);
        }
        if ([entry respondsToSelector:@selector(subsystem)]) {
          NSString *subsystem = [entry subsystem];
          if (subsystem != nil) {
            r["subsystem"] = TEXT([subsystem UTF8String]);
          }
          NSString *category = [entry category];
          if (category != nil) {
            r["category"] = TEXT([category UTF8String]);
          }
        }
        results.push_back(r);
    }
    }
}

QueryData genUnifiedLog(QueryContext& context) {
  QueryData results;
  Row row;
  @autoreleasepool {
    genUnifiedLog(results);
  }
  return results;
}

} // namespace tables
} // namespace osquery
