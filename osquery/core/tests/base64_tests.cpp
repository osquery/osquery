/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/tests/test_util.h>

#include "osquery/core/base64.h"

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
