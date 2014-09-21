// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>

#include <sqlite3.h>

#include "osquery/status.h"
#include "osquery/registry.h"

namespace osquery {
namespace tables {

class TablePlugin {
 public:
  virtual int attachVtable(sqlite3 *db) { return -1; }
  virtual ~TablePlugin(){};

 protected:
  TablePlugin(){};
};

void attachVirtualTables(sqlite3 *db);
}
}

DECLARE_REGISTRY(TablePlugins,
                 std::string,
                 std::shared_ptr<osquery::tables::TablePlugin>)

#define REGISTERED_TABLES REGISTRY(TablePlugins)

#define REGISTER_TABLE(name, decorator) REGISTER(TablePlugins, name, decorator)
