// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/devtools.h"
#include "osquery/events.h"

int main(int argc, char *argv[]) {
  osquery::initOsquery(argc, argv);

  // Start a thread for each appropriate event type
  osquery::registries::faucet(REGISTERED_EVENTTYPES, REGISTERED_EVENTMODULES);
  osquery::EventFactory::delay();

  int retcode = osquery::launchIntoShell(argc, argv);

  // End any event type threads.
  osquery::EventFactory::end();

  return retcode;
}
