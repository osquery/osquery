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

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/enroll.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/registry_factory.h>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(enroll_secret_path);

class EnrollTests : public testing::Test {
 public:
  void SetUp() {
    deleteDatabaseValue(kPersistentSettings, "nodeKey");
    deleteDatabaseValue(kPersistentSettings, "nodeKeyTime");
  }
};

class SimpleEnrollPlugin : public EnrollPlugin {
 protected:
  std::string enroll() { return "fetched_a_node_key"; }
};

// Register our simple enroll plugin.
REGISTER(SimpleEnrollPlugin, "enroll", "test_simple");

TEST_F(EnrollTests, test_enroll_secret_retrieval) {
  // Write an example secret (deploy key).
  FLAGS_enroll_secret_path =
    (fs::path(kTestWorkingDirectory) / "secret.txt").
    make_preferred().string();
  writeTextFile(FLAGS_enroll_secret_path, "test_secret\n", 0600);
  // Make sure the file content was read and trimmed.
  auto secret = getEnrollSecret();
  EXPECT_EQ(secret, "test_secret");
}

TEST_F(EnrollTests, test_enroll_key_retrieval) {
  FLAGS_disable_enrollment = true;
  // Without enrollment, and with an empty nodeKey storage value, no node key
  // will be fetched or returned from cache.
  EXPECT_EQ(getNodeKey("test_simple"), "");

  // Turn the enrollment features back on and expect a key.
  FLAGS_disable_enrollment = false;
  EXPECT_EQ(getNodeKey("test_simple"), "fetched_a_node_key");
}

TEST_F(EnrollTests, test_enroll_key_caching) {
  // Cause a fetch of the node key.
  auto node_key = getNodeKey("test_simple");

  // Now fetch the time the node key was last cached from the database.
  std::string key_time;
  auto status = getDatabaseValue(kPersistentSettings, "nodeKeyTime", key_time);
  EXPECT_TRUE(status.ok());

  // A subsequent call to getNodeKey will return the same node key.
  // But, our simple enroll plugin is not enforcing any secret check and is
  // always returning the same node key.
  auto node_key2 = getNodeKey("test_simple");
  // In most scenarios subsequent calls to EnrollPlugin::enroll and the backing
  // enrollment service will generate and return different node keys.
  EXPECT_EQ(node_key2, node_key);

  // To work around our contrived example we make sure the node time was not
  // updated, meaning no call to EnrollPlugin::enroll occurred.
  std::string key_time2;
  getDatabaseValue(kPersistentSettings, "nodeKeyTime", key_time2);
  EXPECT_EQ(key_time2, key_time);
}
}
