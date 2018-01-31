/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <benchmark/benchmark.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

static void PLIST_parse_content(benchmark::State& state) {
  // Buffer the plist content into memory.
  std::string content;
  readFile(kTestDataPath + "test.plist", content);

  while (state.KeepRunning()) {
    pt::ptree tree;
    auto status = parsePlistContent(content, tree);
  }
}

BENCHMARK(PLIST_parse_content);

static void PLIST_parse_file(benchmark::State& state) {
  while (state.KeepRunning()) {
    pt::ptree tree;
    auto status = parsePlist(kTestDataPath + "test.plist", tree);
  }
}

BENCHMARK(PLIST_parse_file);
}
