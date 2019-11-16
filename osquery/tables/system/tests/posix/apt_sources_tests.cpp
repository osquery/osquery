/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <fstream>

#include <osquery/tables/system/posix/apt_sources.h>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

//#include <osquery/tables/system/posix/known_hosts.h>
//#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

class AptSourcesImplTests : public testing::Test {};

struct AptTestCase {
  std::string input_line;
  std::string base_uri;
  std::string name;
  std::string cache_filename;
};

TEST_F(AptSourcesImplTests, parse_apt_source_line) {
  std::vector<AptTestCase> test_cases = {
      // "deb " is stripped off.
      {"[arch=amd64] https://pkg.osquery.io/deb deb main",
       "https://pkg.osquery.io/deb",
       "pkg.osquery.io/deb deb main",
       "pkg.osquery.io_deb_dists_deb"},
      // "dists" is not used as a section.
      {"https://pkg.osquery.io apt/source/",
       "https://pkg.osquery.io",
       "pkg.osquery.io apt source",
       "pkg.osquery.io_apt_source"},
      // trailing slashes are stripped from URI.s
      {"https://pkg.osquery.io/// apt/source/",
       "https://pkg.osquery.io///",
       "pkg.osquery.io apt source",
       "pkg.osquery.io_apt_source"},
  };

  for (const auto& test_case : test_cases) {
    AptSource apt_source;

    auto s = parseAptSourceLine(test_case.input_line, apt_source);
    ASSERT_TRUE(s.ok()) << "Failed with " << s.getMessage();

    EXPECT_EQ(apt_source.base_uri, test_case.base_uri);
    EXPECT_EQ(apt_source.name, test_case.name);

    auto cache_filename = getCacheFilename(apt_source.cache_file);
    EXPECT_EQ(cache_filename, test_case.cache_filename);
  }
}

} // namespace tables
} // namespace osquery
