// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/devtools.h"

int main(int argc, char *argv[]) {
  return osquery::devtools::launchIntoShell(argc, argv);
}
