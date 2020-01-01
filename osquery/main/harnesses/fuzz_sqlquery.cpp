/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/sql.h>

#include <osquery/main/harnesses/fuzz_utils.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  return osquery::osqueryFuzzerInitialize(argc, argv);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string q((const char*)data, size);
  osquery::QueryData d;
  osquery::query(q, d);

  return 0;
}
