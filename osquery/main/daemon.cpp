// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/thread.hpp>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/registry.h"
#include "osquery/scheduler.h"

int main(int argc, char *argv[]) {
  // you can access this message later via google::ProgramUsage()
  google::SetUsageMessage(
    "\n"
    "  OSQuery - operating system instrumentation framework\n"
    "\n"
    "  Arguments\n"
    "\n"
    "    -help         Show complete help text\n"
    "\n"
  );
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  osquery::InitRegistry::get().run();

  boost::thread scheduler_thread(osquery::scheduler::initialize);

  scheduler_thread.join();

  return 0;
}
