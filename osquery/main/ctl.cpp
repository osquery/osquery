/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <string.h>

#include <glog/logging.h>

#include <osquery/core.h>

namespace osquery {

void printCtlHelp() {
  std::cout << " osqueryctl\n";
}

void printCtlHelpAndExit() {
  printCtlHelp();
  exit(0);
}

void doSomething() {
  std::cout << "doing something\n";
}

typedef void (*PositionalArgFunction)(void);

typedef std::map<std::string, PositionalArgFunction> CommandMap;

const CommandMap kCtlArguments = CommandMap{
  {"start", doSomething},
  {"stop", doSomething},
  {"config-check", doSomething},
  {"status", doSomething},
  {"info", doSomething},
};

}

int main(int argc, char* argv[]) {
  osquery::initOsquery(argc, argv);

  // if osqueryctl was ran on it's own or with a positional argument "help"
  if (argc < 2 || strncmp(argv[1], "help", 4) == 0) {
    osquery::printCtlHelpAndExit();
  }

  auto command_to_run = osquery::kCtlArguments.find(argv[1]);
  if (command_to_run == osquery::kCtlArguments.end()) {
    osquery::printCtlHelpAndExit();
  }

  (*command_to_run->second)();

  return 0;
}
