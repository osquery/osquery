// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/implementations/etc_hosts.h"

#include <vector>
#include <string>

using namespace osquery::db;

namespace osquery { namespace tables {

QueryData genEtcHosts() {
  std::string content = "";
  return parseEtcHostsContent(content);
}

QueryData parseEtcHostsContent(const std::string& content) {
  QueryData results;
  Row row1;
  row1["address"] = "127.0.0.1";
  row1["host_names"] = "localhost";
  results.push_back(row1);

  return results;
}

}}
