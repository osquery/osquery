// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/devtools.h"
#include "osquery/registry.h"

int main(int argc, char *argv[]) {
  osquery::InitRegistry::get().run();
  return osquery::devtools::launchIntoShell(argc, argv);
}
