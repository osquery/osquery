/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <benchmark/benchmark.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/tests/test_util.h>

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
