/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/rot13.h>

#include <string>

namespace osquery {

class Rot13Tests : public testing::Test {};

TEST_F(Rot13Tests, test_ro13) {
  std::string encoded_data = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt";
  std::string decoded_data = rotDecode(encoded_data);
  ASSERT_TRUE(decoded_data == "The quick brown fox jumps over the lazy dog");
}

} // namespace osquery
