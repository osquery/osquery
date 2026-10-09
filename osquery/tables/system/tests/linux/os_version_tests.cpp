/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <fstream>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/tables/system/linux/os_version.h>

namespace osquery {
namespace tables {

namespace fs = boost::filesystem;

namespace {

const std::string kOSReleaseContent =
    "PRETTY_NAME=\"FooBar 1.2.3 LTS\"\n"
    "NAME=\"Test Linux Server\"\n"
    "VERSION_ID=\"1.2.3\"\n"
    "VERSION=\"1.2.3\"\n"
    "VERSION_CODENAME=foobar\n"
    "VARIANT=Server\n"
    "VARIANT_ID=server\n"
    "VERSION_ID=\"1.2.3\"\n"
    "ID=foo\n"
    "ID_LIKE=bar\n"
    "HOME_URL=\"https://www.foo.com/\"\n"
    "SUPPORT_URL=\"https://help.foo.com/\"\n"
    "BUG_REPORT_URL=\"https://bugs.foo.net/bar/\"\n"
    "PRIVACY_POLICY_URL=\"https://www.foo.com/legal/terms-and-policies/"
    "privacy-policy\"\n";

const std::string kOracleReleaseContent = "Oracle Linux Server release 1.2.3\n";
const std::string kRedhatReleaseContent =
    "Red Hat Enterprise Linux Server release 1.2.3 (Santiago)\n";
const std::string kGentooReleaseContent = "Gentoo Base System version 1.2.3\n";

void writeFile(const fs::path& path, const std::string& content) {
  std::ofstream stream(path.string());
  ASSERT_TRUE(stream.is_open());
  stream << content;
}

} // namespace

class OSVersion : public testing::Test {
 protected:
  void SetUp() override {
    directory_ = fs::temp_directory_path() /
                 fs::unique_path("osquery.os_version_tests.%%%%-%%%%");
    fs::create_directories(directory_);
  }

  void TearDown() override {
    fs::remove_all(directory_);
  }

  fs::path directory_;
};

TEST_F(OSVersion, parseOSVersion) {
  struct TestCase {
    std::string name;
    bool oracleRelease;
    bool redhatRelease;
    bool gentooRelease;
    Row want;
  };

  TestCase testCases[] = {
      {"OracleRelease",
       true,
       true,
       false,
       Row({
           {"_id", "1.2.3"},
           {"arch", getMachineArchitecture()},
           {"build", ""},
           {"codename", "foobar"},
           {"major", "1"},
           {"minor", "2"},
           {"name", "Oracle Linux Server"},
           {"patch", "3"},
           {"platform", "foo"},
           {"platform_like", "bar"},
           {"version", "Oracle Linux Server release 1.2.3"},
       })},
      {"RedhatRelease",
       false,
       true,
       false,
       Row({
           {"_id", "1.2.3"},
           {"arch", getMachineArchitecture()},
           {"build", ""},
           {"codename", "foobar"},
           {"major", "1"},
           {"minor", "2"},
           {"name", "Red Hat Enterprise Linux Server"},
           {"patch", "3"},
           {"platform", "rhel"},
           {"platform_like", "rhel"},
           {"version",
            "Red Hat Enterprise Linux Server release 1.2.3 (Santiago)"},
       })},
      {"GentooRelease",
       false,
       false,
       true,
       Row({
           {"_id", "1.2.3"},
           {"arch", getMachineArchitecture()},
           {"build", ""},
           {"codename", "foobar"},
           {"major", "1"},
           {"minor", "2"},
           {"name", "Gentoo Base System"},
           {"patch", "3"},
           {"platform", "gentoo"},
           {"platform_like", "gentoo"},
           {"version", "Gentoo Base System version 1.2.3"},
       })}};

  for (const auto& tc : testCases) {
    writeFile(directory_ / kOSRelease, kOSReleaseContent);
    if (tc.oracleRelease) {
      writeFile(directory_ / kOracleRelease, kOracleReleaseContent);
    }
    if (tc.redhatRelease) {
      writeFile(directory_ / kRedhatRelease, kRedhatReleaseContent);
    }
    if (tc.gentooRelease) {
      writeFile(directory_ / kGentooRelease, kGentooReleaseContent);
    }

    Row got;
    parseOSVersion(directory_.string(), got);

    for (const auto& name :
         {kOSRelease, kOracleRelease, kRedhatRelease, kGentooRelease}) {
      fs::remove(directory_ / name);
    }

    ASSERT_EQ(got, tc.want) << "Test Case Failed: " << tc.name;
  }
}

} // namespace tables
} // namespace osquery
