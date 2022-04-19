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

#include <osquery/sql/sql.h>
#include <osquery/tables/system/posix/authorized_keys.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/scope_guard.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

class AuthorizedKeysTests : public testing::Test {};

TEST_F(AuthorizedKeysTests, basic_authorized_keys) {
  auto directory =
      fs::temp_directory_path() / fs::unique_path("osquery.authorized_keys_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto authorized_keys_file = directory / fs::path("authorized_keys");

  {
    auto fout = std::ofstream(authorized_keys_file.native());
    fout << "# This is a comment\n"
         << "ssh-rsa AAAAB3NzaC1yc2EAAA...41Ev521Ei2hvz7S2QNr1zAiVaOFy5Lwc8Lo+Jk=\n"
         << "ssh-rsa AAAAB3NzaC1yc2EAAA...zAiVaOFy5Lwc8Lo+Jk=  Fred @ Project FOOBAR\n"
         << "command=\"/usr/bin/tinyfugue\" ssh-rsa AAAAB3NzaC1yc2EAAA...OFy5Lwc8Lo+Jk=\n"
         << "environment=\"PATH=/bin:/usr/bin/:/opt/gtm/bin\" ssh-rsa AAAAB3N...4Y2t1j= user@hostname\n"
         << "from=\"*.example.com\",zos-key-ring-label=\"KeyRingOwner/SSHAuthKeysRing uniq-ssh-dsa\"" // valid line
         << "ssh23rsa AAAA...== jane@example.net" // invalid key type
         << "from=\"*.sales.example.net,!pc.sales.example.net\",command=\"dump /home\",no-pty,no-port-forwarding"; // key type and key are missing
  }

  auto results = QueryData{};
  GLOGLogger logger;
  genSSHkeysForUser("0", "0", directory.string(), results, logger);

  ASSERT_EQ(results.size(), 6);

  EXPECT_EQ(results[0].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[0].at("algorithm"), "ssh-rsa");
  EXPECT_EQ(results[0].at("key"), "AAAAB3NzaC1yc2EAAA...41Ev521Ei2hvz7S2QNr1zAiVaOFy5Lwc8Lo+Jk=");
  EXPECT_EQ(results[0].at("comment"), "Fred @ Project FOOBAR");
  EXPECT_TRUE(results[0].at("options").empty());

  EXPECT_EQ(results[1].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[1].at("algorithm"), "ssh-rsa");
  EXPECT_EQ(results[1].at("key"), "AAAAB3NzaC1yc2EAAA...zAiVaOFy5Lwc8Lo+Jk=");
  EXPECT_TRUE(results[1].at("comment").empty());
  EXPECT_TRUE(results[1].at("options").empty());

  EXPECT_EQ(results[2].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[2].at("algorithm"), "ssh-rsa");
  EXPECT_EQ(results[2].at("key"), "AAAAB3NzaC1yc2EAAA...OFy5Lwc8Lo+Jk=");
  EXPECT_EQ(results[2].at("options"), "command=\"/usr/bin/tinyfugue\"");
  EXPECT_TRUE(results[2].at("comment").empty());

  EXPECT_EQ(results[3].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[3].at("algorithm"), "ssh-rsa");
  EXPECT_EQ(results[3].at("key"), "AAAAB3NzaC1yc2EAAA...41Ev521Ei2hvz7S2QNr1zAiVaOFy5Lwc8Lo+Jk=");
  EXPECT_EQ(results[3].at("comment"), "Fred @ Project FOOBAR");
  EXPECT_EQ(results[3].at("options"), "command=\"/usr/bin/tinyfugue\"");

  EXPECT_EQ(results[4].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[4].at("algorithm"), "ssh-rsa");
  EXPECT_EQ(results[4].at("key"), "AAAAB3N...4Y2t1j=");
  EXPECT_EQ(results[4].at("comment"), "user@hostname");
  EXPECT_EQ(results[4].at("options"), "environment=\"PATH=/bin:/usr/bin/:/opt/gtm/bin\"");

  EXPECT_EQ(results[5].at("key_file"), authorized_keys_file.string());
  EXPECT_EQ(results[5].at("options"), "from=\"*.example.com\",zos-key-ring-label=\"KeyRingOwner/SSHAuthKeysRing uniq-ssh-dsa\"");
  EXPECT_TRUE(results[5].at("comment").empty());
  EXPECT_TRUE(results[5].at("key").empty());
  EXPECT_TRUE(results[5].at("algorithm").empty());
}

} // namespace tables
} // namespace osquery
