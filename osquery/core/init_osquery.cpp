// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/registry.h"

namespace osquery {
namespace core {

const std::string kDefaultLogDir = "/var/log/osquery/";

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
  FLAGS_alsologtostderr = true;
  FLAGS_logbufsecs = 0; // flush the log buffer immediately
  FLAGS_stop_logging_if_full_disk = true;
  FLAGS_max_log_size = 1024; // max size for individual log file is 1GB
  FLAGS_log_dir = kDefaultLogDir;
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  osquery::InitRegistry::get().run();
}
}
}
