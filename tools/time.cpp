#include <iostream>

#include "osquery/core.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);
  std::cout << "Calendar Time:  " << osquery::core::getAsciiTime() << "\n";
  std::cout << "Unix Time:      " << osquery::core::getUnixTime() << "\n";
  return 0;
}
