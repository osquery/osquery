// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <cstring>
#include <ctime>
#include <unistd.h>

#include <boost/algorithm/string/trim.hpp>

namespace osquery {
namespace core {

std::string getHostname() {
  char hostname[255];
  memset(hostname, 0, 255);
  gethostname(hostname, 255);
  std::string hostname_string = std::string(hostname);
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getAsciiTime() {
  std::time_t result = std::time(NULL);
  std::string time_str = std::string(std::asctime(std::localtime(&result)));
  boost::algorithm::trim(time_str);
  return time_str;
}

int getUnixTime() {
  std::time_t result = std::time(NULL);
  return result;
}

}
}
