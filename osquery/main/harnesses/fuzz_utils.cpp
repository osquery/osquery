/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

int osqueryFuzzerInitialize(int* argc, char*** argv) {
  osquery::registryAndPluginInit();
  osquery::DatabasePlugin::setAllowOpen(true);
  osquery::Registry::get().setActive("database", "ephemeral");
  osquery::DatabasePlugin::initPlugin().ok();

  osquery::PluginRequest r;
  r["action"] = "detach";
  r["table"] = "file";

  osquery::PluginResponse rsp;
  osquery::Registry::get().call("sql", r, rsp);
  FLAGS_minloglevel = 4;

  return 0;
}
} // namespace osquery
