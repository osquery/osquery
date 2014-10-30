// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <cstring>
#include <ctime>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <boost/algorithm/string/trim.hpp>

namespace osquery {

std::string getHostname() {
  char hostname[256];
  memset(hostname, 0, 255);
  gethostname(hostname, 255);
  std::string hostname_string = std::string(hostname);
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getHostUuid(){
  char uuid[128];
  memset(uuid, 0, 128);
  uuid_t id;
  const timespec wait = {0,0};
  int result = gethostuuid(id, &wait);
  if (result == 0){
    char out[128];
    uuid_unparse(id, out);
    std::string uuid_string = std::string(out);
    boost::algorithm::trim(uuid_string);
    return uuid_string;
  }
  else
    return "";
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
