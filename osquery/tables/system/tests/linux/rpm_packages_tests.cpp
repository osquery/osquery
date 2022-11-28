/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/utils/system/env.h>

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmts.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <utility>

using namespace testing;

namespace osquery {
namespace tables {

rpmlogCallback gPreviousCallback{nullptr};

class RpmTests : public ::testing::Test {
 public:
  static int Callback(rpmlogRec rec, rpmlogCallbackData data) {
    return 0;
  }

 protected:
  void SetUp() {
    gPreviousCallback = rpmlogSetCallback(&RpmTests::Callback, nullptr);
  }

  void setConfig(const std::string& path) {
    config_ = getEnvVar("RPM_CONFIGDIR");
    setEnvVar("RPM_CONFIGDIR", path);
    addMacro(nullptr, "_dbpath", nullptr, path.c_str(), 0);
    addMacro(nullptr, "rpmdb", nullptr, path.c_str(), 0);
  }

  void TearDown() {
    rpmlogSetCallback(gPreviousCallback, nullptr);

    if (config_.is_initialized()) {
      setEnvVar("RPM_CONFIGDIR", *config_);
      config_ = boost::none;
    } else {
      unsetEnvVar("RPM_CONFIGDIR");
    }

    delMacro(nullptr, "_dbpath");
    delMacro(nullptr, "rpmdb");
  }

 private:
  // Previous configuration directory.
  boost::optional<std::string> config_;
};

struct PackageDetails {
  std::string name;
  std::string version;
  std::string sha1;

  friend bool operator==(const PackageDetails& pd1, const PackageDetails& pd2);
  friend std::ostream& operator<<(std::ostream& s, const PackageDetails& pd);
};

bool operator==(const PackageDetails& pd1, const PackageDetails& pd2) {
  return pd1.name == pd2.name && pd1.version == pd2.version &&
         pd1.sha1 == pd2.sha1;
}

std::ostream& operator<<(std::ostream& s, const PackageDetails& pd) {
  s << pd.name << "-" << pd.version << " (" << pd.sha1 << ") ";
  return s;
}

typedef std::function<void(struct PackageDetails&)> packageCallback;

Status queryRpmDb(packageCallback predicate) {
  rpmInitCrypto();
  if (rpmReadConfigFiles(nullptr, nullptr) != 0) {
    rpmFreeCrypto();
    Status::failure("Cannot read configuration");
  }

  rpmts ts = rpmtsCreate();
  auto matches = rpmtsInitIterator(ts, RPMTAG_NAME, nullptr, 0);

  Header header;
  while ((header = rpmdbNextIterator(matches)) != nullptr) {
    rpmtd td = rpmtdNew();

    struct PackageDetails pd;
    if (headerGet(header, RPMTAG_NAME, td, HEADERGET_DEFAULT) != 0) {
      pd.name = rpmtdGetString(td);
    }

    if (headerGet(header, RPMTAG_VERSION, td, HEADERGET_DEFAULT) != 0) {
      pd.version = rpmtdGetString(td);
    }

    if (headerGet(header, RPMTAG_SHA1HEADER, td, HEADERGET_DEFAULT) != 0) {
      pd.sha1 = rpmtdGetString(td);
    }

    rpmtdFree(td);

    predicate(pd);
  }

  rpmdbFreeIterator(matches);
  rpmtsFree(ts);
  rpmFreeCrypto();
  rpmFreeRpmrc();

  return Status::success();
}

TEST_F(RpmTests, test_bdb_packages) {
  auto dropper = DropPrivileges::get();
  if (isUserAdmin()) {
    ASSERT_TRUE(dropper->dropTo("nobody"));
  }

  auto bdb_config = getTestConfigDirectory() / "rpm" / "rpm-bdb";
  bdb_config = boost::filesystem::absolute(bdb_config);
  this->setConfig(bdb_config.string());

  std::vector<struct PackageDetails> packages;
  auto getPackage = [&packages](struct PackageDetails& pd) {
    packages.push_back(pd);
  };

  ASSERT_TRUE(queryRpmDb(getPackage).ok());

  std::vector<struct PackageDetails> expected = {
      {"rpm-libs", "4.8.0", "4bdccd7d66ec292581ae047c73e476869f43c704"},
      {"rpm-python", "4.8.0", "e308afd6a0c0a0dc31ad8dbf64c0bd1651462c02"},
      {"rpm", "4.8.0", "3b1c9206487936ed0d6190a794a2f3c40e3dd5b1"},
  };

  EXPECT_EQ(expected, packages);
};

TEST_F(RpmTests, test_sqlite_packages) {
  auto dropper = DropPrivileges::get();
  if (isUserAdmin()) {
    ASSERT_TRUE(dropper->dropTo("nobody"));
  }

  auto sqlite_config = getTestConfigDirectory() / "rpm" / "rpm-sqlite";
  sqlite_config = boost::filesystem::absolute(sqlite_config);
  this->setConfig(sqlite_config.string());

  std::vector<struct PackageDetails> packages;
  auto getPackage = [&packages](struct PackageDetails& pd) {
    packages.push_back(pd);
  };

  ASSERT_TRUE(queryRpmDb(getPackage).ok());

  std::vector<struct PackageDetails> expected = {
      {"deltarpm", "3.6.2", "b94aeacccb128594c1c385a19a36b7237fd7bd55"},
      {"python3-rpm", "4.16.0", "cb4fd19975ffb22a6c67fa1ced0dd98cf039e2c3"},
      {"rpm", "4.16.0", "f1b7a4ad5d2497a44039ba20a2e83e7e60d52472"},
      {"rpm-build-libs", "4.16.0", "0e964be137e7489228e91d16d16ade7a38474bce"},
      {"rpm-libs", "4.16.0", "4eb167bef01b1c0684f870ef791ec4de3db96ca2"},
      {"rpm-plugin-selinux",
       "4.16.0",
       "2118e44fbdbdcd7bbf8306630bf03c289a6401cc"},
      {"rpm-plugin-systemd-inhibit",
       "4.16.0",
       "74890e714d68b144750b5529617361b4a4f64430"},
      {"rpm-sign-libs", "4.16.0", "01c6d988e05b320c9620e66b8bda57b8dd1749fe"},
      {"systemd-rpm-macros",
       "246.6",
       "50805b7fdfeef333d918a0da76c636e7ef182e36"},
  };

  EXPECT_EQ(expected, packages);
};

TEST_F(RpmTests, test_ndb_packages) {
  auto dropper = DropPrivileges::get();
  if (isUserAdmin()) {
    ASSERT_TRUE(dropper->dropTo("nobody"));
  }

  auto ndb_config = getTestConfigDirectory() / "rpm" / "rpm-ndb";
  ndb_config = boost::filesystem::absolute(ndb_config);
  this->setConfig(ndb_config.string());

  std::vector<struct PackageDetails> packages;
  auto getPackage = [&packages](struct PackageDetails& pd) {
    packages.push_back(pd);
  };

  ASSERT_TRUE(queryRpmDb(getPackage).ok());

  std::vector<struct PackageDetails> expected = {
      {"binutils", "2.35.1", "2e706f0d18f426555620350d5c665f834ae20317"},
      {"zlib-devel", "1.2.11", "202827943881ba133a7e8ca91290dcc71083a8e1"},
      {"ncurses-devel", "6.1", "04c2780ee303bc28ca3568233fe7310d964d3b0c"}};

  EXPECT_EQ(expected, packages);
};

} // namespace tables
} // namespace osquery
