/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/ycloud/ycloud_util.h>

namespace osquery {
namespace {

class YCloudUtilsTests : public testing::Test {};

TEST_F(YCloudUtilsTests, pass) {
  const std::string zone = "projects/b1g1slgali4fssudpn26/zones/ru-central1-a";
  auto [folder_id, zone_id] = getFolderIdAndZoneFromZoneField(zone);
  EXPECT_EQ(folder_id, "b1g1slgali4fssudpn26");
  EXPECT_EQ(zone_id, "ru-central1-a");
}

TEST_F(YCloudUtilsTests, fail) {
  const std::string zone = "projects/b1g1slgali4fssudpn26/zones-ru-central1-a";
  auto [folder_id, zone_id] = getFolderIdAndZoneFromZoneField(zone);
  EXPECT_EQ(folder_id, "");
  EXPECT_EQ(zone_id, "");
}

} // namespace
} // namespace osquery