/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>

namespace fs = boost::filesystem;

namespace osquery {

namespace {
const std::string kHelloString("HELLO");

const std::string kHelloMD5Digest("eb61eead90e3b899c6bcbe27ac581660");
const std::string kHelloSHA1Digest("c65f99f8c5376adadddc46d5cbcf5762f9e55eb7");
const std::string kHelloSHA256Digest(
    "3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5");

const std::string kHelloMD5DigestBase64("62HurZDjuJnGvL4nrFgWYA==");
const std::string kHelloSHA1DigestBase64("xl+Z+MU3atrd3EbVy89XYvnlXrc=");
const std::string kHelloSHA256DigestBase64(
    "NzPNl3/46xi5hzV+Is7Zn0YJfzHssjnoeK5jdg6D5NU=");
} // namespace

class HashingFilesystemTests : public testing::Test {
 protected:
  fs::path test_working_dir_;

  void SetUp() override {
    initializeFilesystemAPILocale();

    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {
    fs::remove_all(test_working_dir_);
  }
};

TEST_F(HashingFilesystemTests, test_multi_hashing_file) {
  auto file_path = test_working_dir_ / "hashing_file.txt";

  std::ofstream test_file(file_path.string());

  test_file.write(kHelloString.c_str(), kHelloString.length());
  test_file.close();

  const auto mask = HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256;
  const auto hashes = hashMultiFromFile(mask, file_path.string());

  EXPECT_EQ(hashes.mask, mask);
  EXPECT_EQ(hashes.md5, kHelloMD5Digest);
  EXPECT_EQ(hashes.sha1, kHelloSHA1Digest);
  EXPECT_EQ(hashes.sha256, kHelloSHA256Digest);

  EXPECT_EQ(hashFromFile(HASH_TYPE_MD5, file_path.string()), kHelloMD5Digest);
  EXPECT_EQ(hashFromFile(HASH_TYPE_SHA1, file_path.string()), kHelloSHA1Digest);
  EXPECT_EQ(hashFromFile(HASH_TYPE_SHA256, file_path.string()),
            kHelloSHA256Digest);
}

TEST(HashingTests, test_hashing_md5) {
  Hash hash(HASH_TYPE_MD5);
  hash.update(kHelloString.c_str(), kHelloString.length());

  auto digest = hash.digest();
  EXPECT_EQ(digest, kHelloMD5Digest);

  Hash hashBase64(HASH_TYPE_MD5, HASH_ENCODING_TYPE_BASE64);
  hashBase64.update(kHelloString.c_str(), kHelloString.length());

  digest = hashBase64.digest();
  EXPECT_EQ(digest, kHelloMD5DigestBase64);

  digest = hashFromBuffer(
      HASH_TYPE_MD5, kHelloString.c_str(), kHelloString.length());
  EXPECT_EQ(digest, kHelloMD5Digest);
}

TEST(HashingTests, test_hashing_sha1) {
  Hash hash(HASH_TYPE_SHA1);
  hash.update(kHelloString.c_str(), kHelloString.length());

  auto digest = hash.digest();
  EXPECT_EQ(digest, kHelloSHA1Digest);

  Hash hashBase64(HASH_TYPE_SHA1, HASH_ENCODING_TYPE_BASE64);
  hashBase64.update(kHelloString.c_str(), kHelloString.length());

  digest = hashBase64.digest();
  EXPECT_EQ(digest, kHelloSHA1DigestBase64);

  digest = hashFromBuffer(
      HASH_TYPE_SHA1, kHelloString.c_str(), kHelloString.length());
  EXPECT_EQ(digest, kHelloSHA1Digest);
}

TEST(HashingTests, test_hashing_sha256) {
  Hash hash(HASH_TYPE_SHA256);
  hash.update(kHelloString.c_str(), kHelloString.length());

  auto digest = hash.digest();
  EXPECT_EQ(digest, kHelloSHA256Digest);

  Hash hashBase64(HASH_TYPE_SHA256, HASH_ENCODING_TYPE_BASE64);
  hashBase64.update(kHelloString.c_str(), kHelloString.length());

  digest = hashBase64.digest();
  EXPECT_EQ(digest, kHelloSHA256DigestBase64);

  digest = hashFromBuffer(
      HASH_TYPE_SHA256, kHelloString.c_str(), kHelloString.length());
  EXPECT_EQ(digest, kHelloSHA256Digest);
}

} // namespace osquery
