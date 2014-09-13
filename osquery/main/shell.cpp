// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/devtools.h"

int main(int argc, char *argv[]) {
  osquery::initOsquery(argc, argv);
  return osquery::launchIntoShell(argc, argv);
}
