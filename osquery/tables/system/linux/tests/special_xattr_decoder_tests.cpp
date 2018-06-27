/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdlib>
#include <string>
#include <unordered_map>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/tables/system/linux/special_xattr_decoder.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {
const std::string kSecurityCapabilityXattr = "security.capability";

class SpecialXattrDecoder : public testing::Test {};

TEST_F(SpecialXattrDecoder, special_xattr_decoder) {
  EXPECT_TRUE(isSpecialExtendedAttribute(kSecurityCapabilityXattr));

  auto test_file_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  {
    std::fstream test_file(test_file_path, std::ios::out);
    ASSERT_EQ(!test_file, false);
  }

  auto command_line = "setcap cap_net_admin+ep \"" + test_file_path + "\"";

  bool succeeded = std::system(command_line.data()) == 0;
  if (!succeeded) {
    if (geteuid() != 0) {
      LOG(WARNING)
          << "setcap failed; are you running as root? Skipping the test...";
      return;
    }

    ASSERT_TRUE(succeeded);
  }

  ExtendedAttributes decoded_attribute;
  succeeded = decodeSpecialExtendedAttribute(
      decoded_attribute, test_file_path, kSecurityCapabilityXattr);
  ASSERT_TRUE(succeeded);

  EXPECT_EQ(decoded_attribute.size(), 1U);
  EXPECT_EQ(decoded_attribute[0].first, kSecurityCapabilityXattr);
  EXPECT_EQ(decoded_attribute[0].second, "cap_net_admin+ep");

  fs::remove(test_file_path);
}
} // namespace osquery
