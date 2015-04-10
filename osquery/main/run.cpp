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

#include <gflags/gflags.h>

#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

DEFINE_string(query, "", "query to execute");
DEFINE_int32(iterations, 1, "times to run the query in question");
DEFINE_int32(delay, 0, "delay before and after the query");

int main(int argc, char* argv[]) {
  // Only log to stderr
  FLAGS_logtostderr = true;

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, false);
  GFLAGS_NAMESPACE::InitGoogleLogging(argv[0]);

  if (FLAGS_query == "") {
    fprintf(stderr, "Usage: %s --query=\"query\"\n", argv[0]);
    return 1;
  }

  osquery::Registry::setUp();
  osquery::attachEvents();

  if (FLAGS_delay != 0) {
    ::sleep(FLAGS_delay);
  }

  osquery::QueryData results;
  osquery::Status status;
  for (int i = 0; i < FLAGS_iterations; ++i) {
    status = osquery::query(FLAGS_query, results);
    if (!status.ok()) {
      fprintf(stderr, "Query failed: %d\n", status.getCode());
      break;
    }
  }

  if (FLAGS_delay != 0) {
    ::sleep(FLAGS_delay);
  }

  // Instead of calling "shutdownOsquery" force the EF to join its threads.
  osquery::EventFactory::end(true);
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();

  return status.getCode();
}
