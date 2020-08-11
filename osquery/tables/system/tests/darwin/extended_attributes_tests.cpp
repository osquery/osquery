/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <sys/xattr.h>

#include <boost/filesystem.hpp>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

std::vector<std::string> parseExtendedAttributeList(const std::string &path);
void parseQuarantineFile(QueryData &results, const std::string &path);
void parseWhereFrom(QueryData &results, const std::string &path);
void getFileData(QueryData &results, const std::string &path);

const std::string kQuarantineKey = "com.apple.quarantine";
const unsigned char kQuarantineValue[] = {
    0x30, 0x30, 0x30, 0x31, 0x3B, 0x35, 0x35, 0x34, 0x39, 0x34, 0x64, 0x65,
    0x33, 0x3B, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x5C, 0x78, 0x32, 0x30,
    0x43, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x3B, 0x36, 0x41, 0x30, 0x45, 0x43,
    0x39, 0x32, 0x44, 0x2D, 0x31, 0x38, 0x38, 0x32, 0x2D, 0x34, 0x33, 0x35,
    0x38, 0x2D, 0x41, 0x33, 0x31, 0x35, 0x2D, 0x35, 0x38, 0x36, 0x42, 0x41,
    0x36, 0x35, 0x46, 0x38, 0x46, 0x37, 0x37};

const std::string kMetedataKey = "com.apple.metadata:kMDItemWhereFroms";
const unsigned char kMetadataWhereFromValue[] = {
    0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x30, 0xA2, 0x01, 0x02, 0x5F,
    0x10, 0x3D, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x64, 0x6C,
    0x2E, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F,
    0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2F, 0x6D, 0x61, 0x63, 0x2F, 0x73,
    0x74, 0x61, 0x62, 0x6C, 0x65, 0x2F, 0x47, 0x47, 0x52, 0x4F, 0x2F, 0x67,
    0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E,
    0x64, 0x6D, 0x67, 0x5F, 0x10, 0x40, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A,
    0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65,
    0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2F,
    0x62, 0x72, 0x6F, 0x77, 0x73, 0x65, 0x72, 0x2F, 0x74, 0x68, 0x61, 0x6E,
    0x6B, 0x79, 0x6F, 0x75, 0x2E, 0x68, 0x74, 0x6D, 0x6C, 0x3F, 0x70, 0x6C,
    0x61, 0x74, 0x66, 0x6F, 0x72, 0x6D, 0x3D, 0x6D, 0x61, 0x63, 0x08, 0x0B,
    0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8E};

const std::string kFsckKey = "com.apple.diskimages.fsck";
const unsigned char kFsckValue[] = {0x38, 0xFF, 0xBE, 0x7E, 0xEF, 0xBE, 0x27,
                                    0xC0, 0x7B, 0x00, 0x6C, 0x88, 0xB2, 0xA1,
                                    0x50, 0x4D, 0x16, 0x70, 0x6C, 0x7A};

const std::string kDiskImagefsckBase64 = "OP++fu++J8B7AGyIsqFQTRZwbHo=";

void removexattrs(const std::string &path) {
  auto xattrs = parseExtendedAttributeList(path);
  for (const auto &xattr : xattrs) {
    removexattr(path.c_str(), xattr.c_str(), XATTR_NOFOLLOW);
  }
}

void setxattrs(const std::string &path) {
  setxattr(path.c_str(), kQuarantineKey.c_str(), (void *)kQuarantineValue,
           sizeof(kQuarantineValue), 0, XATTR_NOFOLLOW);
  setxattr(path.c_str(), kMetedataKey.c_str(), (void *)kMetadataWhereFromValue,
           sizeof(kMetadataWhereFromValue), 0, XATTR_NOFOLLOW);
  setxattr(path.c_str(), kFsckKey.c_str(), (void *)kFsckValue,
           sizeof(kFsckValue), 0, XATTR_NOFOLLOW);
  // insert arbitrary xattr
  const std::string key = "foobar";
  const unsigned char val[] = {0x62, 0x61, 0x7A}; // baz
  setxattr(path.c_str(), key.c_str(), (void *)val, sizeof(val), 0,
           XATTR_NOFOLLOW);
}

class ExtendedAttributesTests : public testing::Test {
 protected:
  virtual void SetUp() {
    removexattrs(kTestFilePath);
    setxattrs(kTestFilePath);
  }

  virtual void TearDown() { removexattrs(kTestFilePath); }

  const std::string kTestFilePath =
      (getTestConfigDirectory() / "test_xattrs.txt").string();
  const std::string kTestFileDir =
      boost::filesystem::path(kTestFilePath).parent_path().string();
};

TEST_F(ExtendedAttributesTests, test_extended_attributes) {
  QueryData results;
  getFileData(results, kTestFilePath);

  const std::map<std::string, std::string> expected = {
      {"quarantine_agent", "Google Chrome"},
      {"quarantine_type", "LSQuarantineTypeWebDownload"},
      {"quarantine_timestamp", "1430867421"},
      {"quarantine_event_id", "6A0EC92D-1882-4358-A315-586BA65F8F77"},
      {"quarantine_data_url",
       "https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg"},
      {"quarantine_origin_url",
       "https://www.google.com/chrome/browser/thankyou.html?platform=mac"},
      {"foobar", "baz"},
      {kFsckKey, kDiskImagefsckBase64}};

  for (auto row : results) {
    for (auto elems : row) {
      auto key = elems.first;
      auto value = elems.second;
      if (expected.count(key) > 0) {
        if (key == "quarantime_timestamp") {
          long timeExpected = std::stol(expected.at("quarantine_timestamp"));
          long actual = std::stol(value);
          EXPECT_GE(timeExpected, actual);
        } else {
          EXPECT_EQ(expected.at(key), value);
        }
      }
    }
  }
}
}
}
