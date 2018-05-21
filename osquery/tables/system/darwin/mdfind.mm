/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreServices/CoreServices.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

typedef std::pair<MDQueryRef, std::string> NamedQuery;

const size_t kMaxQueryWait = 5;

void genResults(const std::vector<NamedQuery>& queries, QueryData& results) {
  // The results can update live from macOS so we stop subscribing to updates
  // so we have a moment in time
  for (const auto& query : queries) {
    MDQueryDisableUpdates(query.first);
  }

  // Get data from all the queries
  for (const auto& query : queries) {
    for (int i = 0; i < MDQueryGetResultCount(query.first); ++i) {
      auto mdi = reinterpret_cast<MDItemRef>(
          const_cast<void*>(MDQueryGetResultAtIndex(query.first, i)));
      CFTypeRef tr = MDItemCopyAttribute(mdi, CFSTR("kMDItemPath"));
      if (tr == nullptr) {
        continue;
      }
      Row r;
      r["path"] = stringFromCFString((CFStringRef)tr);
      r["query"] = query.second;
      results.push_back(r);
      CFRelease(tr);
    }
  }
}

std::vector<NamedQuery> genSpotlightSearches(
    const std::set<std::string>& queries) {
  std::vector<NamedQuery> mdrefs;
  mdrefs.reserve(queries.size());

  // Kick off all the queries
  for (const auto& str_query : queries) {
    CFStringRef cfquery = CFStringCreateWithCString(
        kCFAllocatorDefault, str_query.c_str(), kCFStringEncodingUTF8);
    MDQueryRef query = MDQueryCreate(nullptr, cfquery, nullptr, nullptr);
    CFRelease(cfquery);
    if (query == nullptr) {
      LOG(WARNING) << str_query << " is invalid";
      continue;
    }
    Boolean started = MDQueryExecute(query, static_cast<MDQueryOptionFlags>(0x0));

    // Query could not be started, warn the user and move on
    if (!started) {
      CFRelease(query);
      LOG(WARNING) << "Could not execute mdfind query";
      continue;
    }
    // Push retained query, will release later
    mdrefs.push_back(std::make_pair(query, str_query));
  }

  return mdrefs;
}
  
void releaseQueries(std::vector<NamedQuery>& queries) {
  for (const auto& query : queries) {
    CFRelease(query.first);
  }
}

Status waitForSpotlight(const std::vector<NamedQuery>& queries) {
  // Wait for all the queries
  bool all_done{true};
  for (size_t time_started{getUnixTime()};
       (getUnixTime() - time_started) < kMaxQueryWait;) {
    // The queries run asynchronously in the threads CFRunLoop
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, YES);

    // Check if all the queries are complete
    all_done = true;
    for (const auto& query : queries) {
      all_done &= MDQueryIsGatheringComplete(query.first);
    }
    // If all the queries are complete, don't spin any longer
    if (all_done) {
      return Status{0};
    }
  }
  if (!all_done) {
    LOG(WARNING) << "Timed out waiting for queries";
    for (const auto& query : queries) {
      MDQueryStop(query.first);
    }
    return Status{1};
  }
  return Status{0};
}

QueryData genMdfindResults(QueryContext& context) {
  QueryData results;
  auto query_strings = context.constraints["query"].getAll(EQUALS);

  auto queries = genSpotlightSearches(query_strings);
  
  if (!waitForSpotlight(queries).ok()) {
    releaseQueries(queries);
    return results;
  }

  genResults(queries, results);
  releaseQueries(queries);

  return results;
}
}
}
