/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <errno.h>

#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/database/db_handle.h"
#include "osquery/sql/sqlite_util.h"

DEFINE_string(query, "", "query to execute");
DEFINE_int32(iterations, 1, "times to run the query in question");
DEFINE_int32(delay, 0, "delay before and after the query");

namespace osquery {

DECLARE_bool(disable_events);
DECLARE_bool(registry_exceptions);
}

int main(int argc, char* argv[]) {
  // Only log to stderr
  FLAGS_logtostderr = true;

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, false);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_query == "") {
    fprintf(stderr, "Usage: %s --query=\"query\"\n", argv[0]);
    return 1;
  }

  osquery::DBHandle::setAllowOpen(true);
  osquery::FLAGS_database_path = "/dev/null";
  osquery::Registry::setUp();
  osquery::FLAGS_disable_events = true;
  osquery::FLAGS_registry_exceptions = true;
  osquery::attachEvents();

  if (FLAGS_delay != 0) {
    ::sleep(FLAGS_delay);
  }

  osquery::QueryData results;
  osquery::Status status;
  for (int i = 0; i < FLAGS_iterations; ++i) {
    auto dbc = osquery::SQLiteDBManager::get();
    status = osquery::queryInternal(FLAGS_query, results, dbc.db());
    if (!status.ok()) {
      fprintf(stderr, "Query failed: %d\n", status.getCode());
      break;
    }
  }

  if (FLAGS_delay != 0) {
    ::sleep(FLAGS_delay);
  }

  // Instead of calling "shutdownOsquery" force the EF to join its threads.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();

  return status.getCode();
}
