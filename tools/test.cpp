#include <iostream>

#include "osquery/core.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);
  return 0;
}
