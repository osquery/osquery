// Copyright 2004-present Facebook. All Rights Reserved.

#include <glog/logging.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genOsqueryInfo(QueryContext& context) {
  QueryData results;

  Row r;
  r["version"] = TEXT(OSQUERY_VERSION);
  r["pid"] = INTEGER(getpid());

  std::string hash_string;
  auto s = Config::getInstance()->getMD5(hash_string);
  if (s.ok()) {
    r["md5"] = TEXT(hash_string);
  } else {
    LOG(ERROR) << "Could not retrieve config hash: " << s.toString();
  }

  results.push_back(r);

  return results;
}
}
}
