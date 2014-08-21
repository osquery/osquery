#include <iostream>

#include "osquery/core.h"

int main(int argc, char *argv[]) {
  osquery::core::initOsquery(argc, argv);
  std::string sql = "SELECT * FROM kextstat;";
  int err = 0;
  osquery::core::aggregateQuery(sql, err);
  if (err != 0) {
    std::cout << "Error: " << err << "\n";
  }
  return 0;
}
