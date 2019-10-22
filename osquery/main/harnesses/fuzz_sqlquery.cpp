/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/system.h>
#include <osquery/tables.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string q((const char*)data, size);
  osquery::QueryData d;
  osquery::query(q, d);

  return 0;
}
