// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/registry.h"

namespace osquery {
namespace core {

void initOsquery(int argc, char *argv[]) {
  // you can access this message later via google::ProgramUsage()
  google::SetUsageMessage(
      "\n"
      "  OSQuery - operating system instrumentation framework\n"
      "\n"
      "  Arguments\n"
      "\n"
      "    -help         Show complete help text\n"
      "\n");
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = 1;
  osquery::InitRegistry::get().run();
}
}
}
