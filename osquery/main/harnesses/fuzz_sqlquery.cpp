/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/sql.h>

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
