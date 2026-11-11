/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/events/pathset.h>

namespace osquery {

class PathSetTests : public testing::Test {
 protected:
  void SetUp() override {
    // PathSet::insert canonicalizes the part of a pattern before any
    // wildcard. These paths do not exist, so they are stored unchanged on
    // every platform (on macOS, for example, /var and /etc are symlinks).
    paths_.insert("/osquery_pathset_test/excluded");
    paths_.insert("/osquery_pathset_test/logs/*");
  }

  PathSet<patternedPath> paths_;
};

TEST_F(PathSetTests, test_patterned_path_find) {
  EXPECT_TRUE(paths_.find("/osquery_pathset_test/excluded"));
  EXPECT_TRUE(paths_.find("/osquery_pathset_test/logs/syslog"));
  EXPECT_FALSE(paths_.find("/osquery_pathset_test/other"));
  EXPECT_FALSE(paths_.find("/osquery_pathset_test"));
}

TEST_F(PathSetTests, test_patterned_path_find_empty) {
  // The inotify publisher looks up the parent of each event path in the
  // exclude paths. For a top-level path such as "/passwd" that parent is "",
  // which used to make the comparator read out of bounds.
  EXPECT_FALSE(paths_.find(""));
  EXPECT_FALSE(paths_.find("/passwd"));
}

} // namespace osquery
