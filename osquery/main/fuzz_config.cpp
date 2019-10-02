/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config.h>
#include <osquery/database.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

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

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string q((const char*)data, size);
  osquery::Config::get().update({{"fuzz", q}});

  return 0;
}
