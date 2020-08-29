/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>

#include <osquery/tables/system/posix/known_hosts.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

class KnownHostsImplTests : public testing::Test {};

TEST_F(KnownHostsImplTests, get_from_file) {
  namespace fs = boost::filesystem;

  auto results = QueryData{};
  auto directory = fs::temp_directory_path() /
                   fs::unique_path("osquery.known_hosts_impl_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto ssh_directory = directory / fs::path(".ssh");

  ASSERT_TRUE(fs::create_directories(ssh_directory));

  auto filepath = ssh_directory / fs::path("known_hosts");

  auto const first_line =
      R"raw(github.com,11:da:3a2a:3a2s:a0a0:0:2:1 ssh-rsa ZmIK)raw";
  auto const second_line = R"raw(gist.github.com ssh-rsa bmlsCg==)raw";
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << first_line << '\n';
    fout << second_line << '\n';
  }

  auto const uid = std::to_string(geteuid());
  auto const gid = std::to_string(getegid());

  impl::genSSHkeysForHosts(uid, gid, directory.string(), results);
  ASSERT_EQ(results.size(), 2);

  const auto& first_row = results[0];
  EXPECT_EQ(first_row.at("key"), first_line);
  EXPECT_EQ(first_row.at("uid"), uid);
  EXPECT_EQ(first_row.at("key_file"), filepath.string());

  const auto& second_row = results[1];
  EXPECT_EQ(second_row.at("key"), second_line);
  EXPECT_EQ(second_row.at("uid"), uid);
  EXPECT_EQ(second_row.at("key_file"), filepath.string());
}

} // namespace tables
} // namespace osquery
