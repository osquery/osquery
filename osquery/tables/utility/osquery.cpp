/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/extensions.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

void genFlag(const std::string& name,
             const FlagDetail& flag,
             bool is_shell,
             QueryData& results) {
  Row r;
  r["name"] = name;
  r["type"] = std::get<0>(flag);
  r["description"] = std::get<2>(flag);
  r["default_value"] = std::get<1>(flag);
  r["value"] = Flag::get().getValue(name);
  r["shell_only"] = (is_shell) ? "1" : "0";
  results.push_back(r);
}

QueryData genOsqueryFlags(QueryContext& context) {
  QueryData results;

  auto flags = Flag::get().flags();
  for (const auto& flag : flags) {
    genFlag(flag.first, flag.second, false, results);
  }

  auto shell_flags = Flag::get().shellFlags();
  for (const auto& flag : shell_flags) {
    genFlag(flag.first, flag.second, true, results);
  }

  return results;
}

QueryData genOsqueryInfo(QueryContext& context) {
  QueryData results;

  Row r;
  r["version"] = TEXT(OSQUERY_VERSION);
  r["pid"] = INTEGER(getpid());

  std::string hash_string;
  auto s = Config::getInstance()->getMD5(hash_string);
  if (s.ok()) {
    r["config_md5"] = TEXT(hash_string);
  } else {
    r["config_md5"] = "";
    VLOG(1) << "Could not retrieve config hash: " << s.toString();
  }

  r["config_path"] = Flag::get().getValue("config_path");
  r["extensions"] =
      (pingExtension(FLAGS_extensions_socket).ok()) ? "active" : "inactive";
  results.push_back(r);

  return results;
}
}
}
