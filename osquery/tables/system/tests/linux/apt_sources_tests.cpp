/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <osquery/tables/system/linux/apt_sources.h>

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
      // normal line
      {"deb [arch=amd64] https://pkg.osquery.io/deb bionic main",
       "https://pkg.osquery.io/deb",
       "pkg.osquery.io/deb bionic",
       "pkg.osquery.io_deb_dists_bionic"},
      // extra leading spaces
      {"      deb [arch=amd64] https://pkg.osquery.io/deb bionic main",
       "https://pkg.osquery.io/deb",
       "pkg.osquery.io/deb bionic",
       "pkg.osquery.io_deb_dists_bionic"},
      // "dists" is not used in the cache name
      {"deb https://pkg.osquery.io apt/source/",
       "https://pkg.osquery.io",
       "pkg.osquery.io apt/source/",
       "pkg.osquery.io_apt_source"},
      // trailing slashes are stripped from URIs
      {"deb https://pkg.osquery.io/// apt/source/",
       "https://pkg.osquery.io",
       "pkg.osquery.io apt/source/",
       "pkg.osquery.io_apt_source"},
      // trailing comments are ok
      {"deb https://pkg.osquery.io deb main # this is a trailing comment",
       "https://pkg.osquery.io",
       "pkg.osquery.io deb",
       "pkg.osquery.io_dists_deb"},
      // components aren't required
      {"deb https://pkg.osquery.io deb",
       "https://pkg.osquery.io",
       "pkg.osquery.io deb",
       "pkg.osquery.io_dists_deb"},
      // multiple options are ok
      {"deb [arch=amd64 trusted=yes,no] https://pkg.osquery.io deb main",
       "https://pkg.osquery.io",
       "pkg.osquery.io deb",
       "pkg.osquery.io_dists_deb"},
      // multiple components is ok
      {"deb https://pkg.osquery.io deb main universe multiverse restricted",
       "https://pkg.osquery.io",
       "pkg.osquery.io deb",
       "pkg.osquery.io_dists_deb"},
      // ftp repos ok
      {"deb ftp://pkg.osquery.io deb main universe multiverse restricted",
       "ftp://pkg.osquery.io",
       "pkg.osquery.io deb",
       "pkg.osquery.io_dists_deb"},
  };

  for (const auto& test_case : test_cases) {
    AptSource apt_source;

    auto s = parseAptSourceLine(test_case.input_line, apt_source);
    ASSERT_TRUE(s.ok()) << "Test case \"" << test_case.input_line
                        << "\" Failed with " << s.getMessage();

    EXPECT_EQ(apt_source.base_uri, test_case.base_uri);
    EXPECT_EQ(apt_source.name, test_case.name);

    auto cache_filename = getCacheFilename(apt_source.cache_file);
    EXPECT_EQ(cache_filename, test_case.cache_filename);
  }
}

TEST_F(AptSourcesImplTests, test_failures) {
  AptSource apt_source;

  auto s = parseAptSourceLine(
      "debby [arch=amd64] https://pkg.osquery.io/bionic something main",
      apt_source);
  EXPECT_FALSE(s.ok()) << "no deb prefix";

  s = parseAptSourceLine(
      "debby [arch=amd64] https://pkg.osquery.io/deb deb main", apt_source);
  EXPECT_FALSE(s.ok()) << "deb elsewhere in line, no protocol found";

  s = parseAptSourceLine("# this is entirely a comment line", apt_source);
  ASSERT_FALSE(s.ok()) << "Comment line is invalid";

  s = parseAptSourceLine("   # comment https://pkg.osquery.io", apt_source);
  ASSERT_FALSE(s.ok()) << "Comment line is invalid";

  s = parseAptSourceLine("", apt_source);
  ASSERT_FALSE(s.ok()) << "Empty line is invalid";

  s = parseAptSourceLine("deb [arch=amd64] https:/pkg.osquery.io/deb deb main",
                         apt_source);
  EXPECT_FALSE(s.ok()) << "bad protocol";

  s = parseAptSourceLine("deb pkg.osquery.io", apt_source);
  EXPECT_FALSE(s.ok()) << "Protocol is required";

  s = parseAptSourceLine("deb [some=stuff more=stuff and=more] pkg.osquery.io",
                         apt_source);
  EXPECT_FALSE(s.ok()) << "Protocol is required";

  s = parseAptSourceLine(
      "deb [some=stuff more=stuff and=more] https://pkg.osquery.io",
      apt_source);
  EXPECT_FALSE(s.ok()) << "suite is required";

  s = parseAptSourceLine("deb [arch=amd64] https:// deb main", apt_source);
  EXPECT_FALSE(s.ok()) << "empty uri";

  s = parseAptSourceLine("deb https://pkg.osquery.io # deb main", apt_source);
  ASSERT_FALSE(s.ok()) << "incomplete line no suite";

  s = parseAptSourceLine("deb [option=1 options=2   ]", apt_source);
  ASSERT_FALSE(s.ok()) << "incomplete line no protocol";

  s = parseAptSourceLine(
      "deb [arch=amd64 trusted=yes,no https://pkg.osquery.io deb main",
      apt_source);
  ASSERT_FALSE(s.ok()) << "incomplete line run on options:";
}

TEST_F(AptSourcesImplTests, parse_deb_822_block) {
  std::vector<AptTestCase> test_cases = {
      // normal line
      {"Types: deb \n\
URIs: https://pkg.osquery.io/deb \n\
InvalidOption:\n\
# Commented Line\n\
Suites: noble \n\
Components: main \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "https://pkg.osquery.io/deb",
       "pkg.osquery.io/deb noble",
       "pkg.osquery.io_deb_dists_noble"},
      // extra leading spaces
      {"Types:          deb \n\
URIs:          https://pkg.osquery.io/deb \n\
Suites: noble \n\
Components: main \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "https://pkg.osquery.io/deb",
       "pkg.osquery.io/deb noble",
       "pkg.osquery.io_deb_dists_noble"},
      // "dists" is not used in the cache name
      {"Types: deb \n\
URIs: https://pkg.osquery.io \n\
Suites: noble/other \n\
Components: main \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "https://pkg.osquery.io",
       "pkg.osquery.io noble/other",
       "pkg.osquery.io_noble_other"},
      // trailing slashes are stripped from URIs
      {"Types: deb \n\
URIs: https://pkg.osquery.io//// \n\
Suites: noble \n\
Components: main \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "https://pkg.osquery.io",
       "pkg.osquery.io noble",
       "pkg.osquery.io_dists_noble"},
      // trailing comments are ok
      {"Types: deb # commented line \n\
uris: https://pkg.osquery.io \n\
# Entire commented line \n\
suites: noble \n\
Components: main # trailing comment \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "https://pkg.osquery.io",
       "pkg.osquery.io noble",
       "pkg.osquery.io_dists_noble"},
      // ftp repos ok
      {"Types: deb \n\
URIs: ftp://pkg.osquery.io \n\
Suites: noble \n\
Components: main \n\
Signed-By: /usr/share/keyrings/osquery-archive-keyring.gpg",
       "ftp://pkg.osquery.io",
       "pkg.osquery.io noble",
       "pkg.osquery.io_dists_noble"},
  };

  for (const auto& test_case : test_cases) {
    std::vector<AptSource> apt_sources;

    auto s = parseDeb822Block(test_case.input_line, apt_sources);
    ASSERT_TRUE(s.ok()) << "Test case \"" << test_case.input_line
                        << "\" Failed with " << s.getMessage();

    EXPECT_EQ(apt_sources[0].base_uri, test_case.base_uri);
    EXPECT_EQ(apt_sources[0].name, test_case.name);

    auto cache_filename = getCacheFilename(apt_sources[0].cache_file);
    EXPECT_EQ(cache_filename, test_case.cache_filename);
  }
}

TEST_F(AptSourcesImplTests, test_deb822_failures) {
  std::vector<AptSource> apt_sourecs;

  auto s = parseDeb822Block("", apt_sourecs);
  EXPECT_FALSE(s.ok()) << "missing valid URIs";
  EXPECT_EQ(apt_sourecs.size(), 0);

  s = parseDeb822Block("URIs: http://example.com", apt_sourecs);
  EXPECT_FALSE(s.ok()) << "missing Suites";
  EXPECT_EQ(apt_sourecs.size(), 0);

  s = parseDeb822Block("URIs: example.com http://example.com\nSuites: main",
                       apt_sourecs);
  EXPECT_TRUE(s.ok()) << "missing URL protocol skips that URL";
  EXPECT_EQ(apt_sourecs.size(), 1);
  apt_sourecs.clear();

  s = parseDeb822Block("URIs: http://example.com\nSuites: main\nEnabled: off",
                       apt_sourecs);
  EXPECT_TRUE(s.ok()) << "disabled source";
  EXPECT_EQ(apt_sourecs.size(), 0);
}

} // namespace tables
} // namespace osquery
