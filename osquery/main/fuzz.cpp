/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

/* Use these defines to flip the fuzzing harnesses. */
// #define OSQUERY_FUZZ_SQL
// #define OSQUERY_FUZZ_SMBIOS
#define OSQUERY_FUZZ_CONFIG

void init() {
  osquery::registryAndPluginInit();
  osquery::DatabasePlugin::setAllowOpen(true);
  osquery::Registry::get().setActive("database", "ephemeral");
  osquery::DatabasePlugin::initPlugin().ok();

  osquery::PluginRequest r;
  r["action"] = "detach";
  r["table"] = "file";

  osquery::PluginResponse rsp;
  osquery::Registry::get().call("sql", r, rsp);
}

/**
 * Example: This will fuzz SMBIOS content, which is not user-controllable.
 */
#ifdef OSQUERY_FUZZ_SMBIOS

#include "osquery/tables/system/smbios_utils.h"

class FuzzSMBIOSParser : public osquery::tables::SMBIOSParser {
 public:
  FuzzSMBIOSParser(const uint8_t* data, size_t size) {
    table_data_ = (uint8_t*)malloc(size);
    table_size_ = size;
    memcpy(table_data_, data, size);
  }

 public:
  virtual ~FuzzSMBIOSParser() {
    if (table_data_ != nullptr) {
      free(table_data_);
      table_data_ = nullptr;
    }
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool setup = false;
  if (!setup) {
    init();
    setup = true;
  }

  FuzzSMBIOSParser parser(data, size);
  osquery::QueryData results;

  parser.tables(([&results](size_t index,
                            const osquery::tables::SMBStructHeader* hdr,
                            uint8_t* address,
                            uint8_t* textAddrs,
                            size_t size) {
    genSMBIOSTable(index, hdr, address, size, results);
    genSMBIOSMemoryDevices(index, hdr, address, textAddrs, size, results);
    genSMBIOSMemoryArrays(index, hdr, address, size, results);
    genSMBIOSMemoryArrayMappedAddresses(index, hdr, address, size, results);
    genSMBIOSMemoryErrorInfo(index, hdr, address, size, results);
    genSMBIOSMemoryDeviceMappedAddresses(index, hdr, address, size, results);
  }));

  return 0;
}
#endif

/**
 * Example: This will mostly fuzz SQLites internals.
 */
#ifdef OSQUERY_FUZZ_SQL
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool setup = false;
  if (!setup) {
    init();
    setup = true;
  }

  std::string q((const char*)data, size);
  std::transform(q.begin(), q.end(), q.begin(), ::tolower);

  // Short circuit the file table.
  if (q.find("from file") != std::string::npos) {
    return 0;
  }

  osquery::QueryData r;
  osquery::query(q, r);
  return 0;
}
#endif

/**
 * Example: This will fuzz configuration handling and the config parsers.
 */
#ifdef OSQUERY_FUZZ_CONFIG
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool setup = false;
  if (!setup) {
    init();
    setup = true;
  }

  std::string q((const char*)data, size);
  osquery::Config::get().update({{"fuzz", q}});

  return 0;
}
#endif
