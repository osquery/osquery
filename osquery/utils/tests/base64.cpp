/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/base64.h>

namespace osquery {

class Base64Tests : public testing::Test {};

TEST_F(Base64Tests, test_base64) {
  std::string unencoded = "HELLO";
  auto encoded = base64::encode(unencoded);
  EXPECT_NE(encoded.size(), 0U);

  auto unencoded2 = base64::decode(encoded);
  EXPECT_EQ(unencoded, unencoded2);
}

} // namespace osquery
