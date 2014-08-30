// Copyright 2004-present Facebook. All Rights Reserved.

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core.h"

DEFINE_string(query, "", "query to execute");

int main(int argc, char* argv[]) {
  osquery::core::initOsquery(argc, argv);

  if (FLAGS_query != "") {
    int err;
    LOG(INFO) << "Executing: " << FLAGS_query;
    osquery::core::aggregateQuery(FLAGS_query, err);
    if (err != 0) {
      LOG(ERROR) << "Query failed: " << err;
      return 1;
    }
    LOG(INFO) << "Query succedded";
  } else {
    LOG(ERROR) << "Usage: run --query=\"<query>\"";
    return 1;
  }

  return 0;
}
