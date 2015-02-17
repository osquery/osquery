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
             const FlagInfo& flag,
             QueryData& results) {
  Row r;
  r["name"] = name;
  r["type"] = flag.type;
  r["description"] = flag.description;
  r["default_value"] = flag.default_value;
  r["value"] = flag.value;
  r["shell_only"] = (flag.detail.shell) ? "1" : "0";
  results.push_back(r);
}

QueryData genOsqueryFlags(QueryContext& context) {
  QueryData results;

  auto flags = Flag::flags();
  for (const auto& flag : flags) {
    genFlag(flag.first, flag.second, results);
  }

  return results;
}

QueryData genOsqueryExtensions(QueryContext& context) {
  QueryData results;

  ExtensionList extensions;
  if (!getExtensions(extensions).ok()) {
    return {};
  }

  for (const auto& extenion : extensions) {
    Row r;
    r["uuid"] = TEXT(extenion.first);
    r["name"] = extenion.second.name;
    r["version"] = extenion.second.version;
    r["sdk_version"] = extenion.second.sdk_version;
    r["socket"] = getExtensionSocket(extenion.first);
    results.push_back(r);
  }

  return results;
}

QueryData genOsqueryInfo(QueryContext& context) {
  QueryData results;

  Row r;
  r["version"] = TEXT(OSQUERY_VERSION);
  r["pid"] = INTEGER(getpid());

  std::string hash_string;
  auto s = Config::getInstance().getMD5(hash_string);
  if (s.ok()) {
    r["config_md5"] = TEXT(hash_string);
  } else {
    r["config_md5"] = "";
    VLOG(1) << "Could not retrieve config hash: " << s.toString();
  }

  r["config_path"] = Flag::getValue("config_path");
  r["extensions"] =
      (pingExtension(FLAGS_extensions_socket).ok()) ? "active" : "inactive";
  results.push_back(r);

  return results;
}
}
}
