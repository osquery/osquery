// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/devtools.h"
#include "osquery/events.h"

int main(int argc, char *argv[]) {
  osquery::initOsquery(argc, argv);

  // Start a thread for each appropriate event type
  osquery::registries::faucet(REGISTERED_EVENTPUBLISHERS,
                              REGISTERED_EVENTSUBSCRIBERS);
  osquery::EventFactory::delay();

  osquery::FLAGS_db_path = "/tmp/rocksdb-osquery-shell";
  int retcode = osquery::launchIntoShell(argc, argv);

  // End any event type threads.
  osquery::EventFactory::end();
  return retcode;
}
