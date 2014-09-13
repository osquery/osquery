// Copyright 2004-present Facebook. All Rights Reserved.

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core.h"

DEFINE_string(query, "", "query to execute");
DEFINE_int32(iterations, 1, "times to run the query in question");

int main(int argc, char* argv[]) {
  osquery::initOsquery(argc, argv);

  if (FLAGS_query != "") {
    for (int i = 0; i < FLAGS_iterations; ++i) {
      int err;
      LOG(INFO) << "Executing: " << FLAGS_query;
      osquery::aggregateQuery(FLAGS_query, err);
      if (err != 0) {
        LOG(ERROR) << "Query failed: " << err;
        return 1;
      }
      LOG(INFO) << "Query succedded";
    }
  } else {
    LOG(ERROR) << "Usage: run --query=\"<query>\"";
    return 1;
  }

  return 0;
}
