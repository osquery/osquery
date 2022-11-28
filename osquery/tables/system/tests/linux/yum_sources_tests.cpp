/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <gtest/gtest.h>

#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

void parseYumConf(std::istream&, QueryData& ults, std::string& repos_dir);

class YumSourcesTests : public testing::Test {};

TEST_F(YumSourcesTests, parse_empty_yum_conf) {
  QueryData results;
  std::string repos_dir;
  std::istringstream stream1("");
  parseYumConf(stream1, results, repos_dir);
  // Default is used when no main.reposdir is set
  ASSERT_EQ(repos_dir, "/etc/yum.repos.d");
  ASSERT_EQ(results.size(), (unsigned long)0);
}

TEST_F(YumSourcesTests, parse_yum_conf) {
  QueryData results;
  std::string repos_dir;
  std::istringstream stream2(R"STRLIT(
# Some comment

[main]
cachedir=/var/cache/yum
# This should override the default
reposdir=/etc/local/yum.repos.d

[personal]
baseurl=http://my.repo.url/1/v2/3
enabled=1
name=My personal repo
reposdir=/ignored/path
mirrorlist=http://url.to.mirror.list

[math]
baseurl=http://some.math.repo.url
enabled=0
name=Mathematic library repo
gpgcheck=0
gpgkey=ftp://repokeys/mykey
mirrorlist=http://url.to.mirror.list
)STRLIT");

  parseYumConf(stream2, results, repos_dir);
  ASSERT_EQ(repos_dir, "/etc/local/yum.repos.d");
  ASSERT_EQ(results.size(), (unsigned long)2);

  ASSERT_EQ(results.at(0).at("baseurl"), "http://my.repo.url/1/v2/3");
  ASSERT_EQ(results.at(0).at("mirrorlist"), "http://url.to.mirror.list");
  ASSERT_EQ(results.at(0).at("enabled"), "1");
  ASSERT_EQ(results.at(0).at("name"), "My personal repo");
  ASSERT_EQ(results.at(0).find("gpgcheck"), results.at(0).end());
  ASSERT_EQ(results.at(0).find("gpgkey"), results.at(0).end());

  ASSERT_EQ(results.at(1).at("baseurl"), "http://some.math.repo.url");
  ASSERT_EQ(results.at(1).at("mirrorlist"), "http://url.to.mirror.list");
  ASSERT_EQ(results.at(1).at("enabled"), "0");
  ASSERT_EQ(results.at(1).at("name"), "Mathematic library repo");
  ASSERT_EQ(results.at(1).at("gpgcheck"), "0");
  ASSERT_EQ(results.at(1).at("gpgkey"), "ftp://repokeys/mykey");
}

} // namespace tables
} // namespace osquery
