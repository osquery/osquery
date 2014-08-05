// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/devtools.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);
  return osquery::devtools::launchIntoShell(argc, argv);
}
