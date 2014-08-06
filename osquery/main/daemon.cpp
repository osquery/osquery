// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/thread.hpp>

#include "osquery/core.h"
#include "osquery/scheduler.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);

  boost::thread scheduler_thread(osquery::scheduler::initialize);

  scheduler_thread.join();

  return 0;
}
