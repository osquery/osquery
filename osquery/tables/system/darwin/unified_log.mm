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
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

void genUnifiedLog(QueryContext& context, QueryData &results) {

    if (@available(macOS 10.15, *)) {
    NSError *error = nil;
    OSLogStore *logstore = [OSLogStore localStoreAndReturnError:&error];
    if (error != nil) {
        NSLog(@"error getting handle to log store: %@", error);
        return;
    }

    OSLogPosition *position = nil;

    NSMutableArray *subpredicates = [[NSMutableArray alloc] init];
    if (context.hasConstraint("timestamp", GREATER_THAN)) {
        auto start_time = context.constraints["timestamp"].getAll(GREATER_THAN);
        if (start_time.size() > 1) {
            VLOG(1) << "Received multiple constraint values for timestamp > constraint.  "
                       "Only the first will be evaluated.";
        }

        double provided_timestamp = [[NSString stringWithUTF8String:start_time.begin()->c_str()] doubleValue];
        NSDate *provided_date = [NSDate dateWithTimeIntervalSince1970:provided_timestamp];
        [subpredicates addObject:[NSPredicate predicateWithFormat:@"date > %@", provided_date]];

        position = [logstore positionWithDate:provided_date];
    }

    if (context.hasConstraint("timestamp", LESS_THAN)) {
        auto end_time = context.constraints["timestamp"].getAll(LESS_THAN);
        if (end_time.size() > 1) {
            VLOG(1) << "Received multiple constraing values for timestamp < constraint.  "
                       "Only the first will be evaluated.";
        }

        double provided_timestamp = [[NSString stringWithUTF8String:end_time.begin()->c_str()] doubleValue];
        [subpredicates addObject:[NSPredicate predicateWithFormat:@"date < %@", [NSDate dateWithTimeIntervalSince1970: provided_timestamp]]];
    }

    if (context.hasConstraint("subsystem", EQUALS)) {
        auto subsystem = context.constraints["subsystem"].getAll(EQUALS);
        [subpredicates addObject:[NSPredicate predicateWithFormat:@"subsystem == %@", [NSString stringWithUTF8String:subsystem.begin()->c_str()]]];
    }


    NSPredicate *predicate = [NSCompoundPredicate andPredicateWithSubpredicates:subpredicates];

    OSLogEnumeratorOptions option = 0;
    OSLogEnumerator *enumerator = [logstore entriesEnumeratorWithOptions:option
                                                                position:position
                                                               predicate:predicate
                                                                   error:&error];
    if (error != nil) {
        NSLog(@"error enumerating entries in system log: %@", error);
        return;
    }
    for (OSLogEntryLog *entry in enumerator) {
        Row r;
        r["timestamp"] = BIGINT([[entry date] timeIntervalSince1970]);
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
  @autoreleasepool {
    genUnifiedLog(context, results);
  }
  return results;
}

} // namespace tables
} // namespace osquery
