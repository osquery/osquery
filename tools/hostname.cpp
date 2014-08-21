#include <iostream>

#include "osquery/core.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);
  std::cout << osquery::core::getHostname() << std::endl;
  return 0;
}
