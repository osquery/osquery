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
#include <osquery/worker/logging/include/logger.h>

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

#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

using namespace testing;

namespace osquery {
namespace tables {

// Internal test seam; this helper is not part of an installed public API.
std::string getRpmAttribute(const Header& header,
                            rpmTag tag,
                            const rpmtd& td,
                            Logger& logger);

// BEGIN RPM ATTRIBUTE REGRESSIONS
class RpmAttributeLogger final : public Logger {
 public:
  void log(int, const std::string&) override {
    ADD_FAILURE() << "Unexpected non-verbose diagnostic";
  }

  void vlog(int severity, const std::string& message) override {
    EXPECT_EQ(severity, 1);
    messages.push_back(message);
  }

  std::vector<std::string> messages;
};

class RpmAttributeTests : public ::testing::Test {
 protected:
  void SetUp() override {
    header = headerNew();
    td = rpmtdNew();
    ASSERT_NE(header, nullptr);
    ASSERT_NE(td, nullptr);
  }

  void TearDown() override {
    rpmtdFree(td);
    headerFree(header);
  }

  Header header{nullptr};
  rpmtd td{nullptr};
  RpmAttributeLogger logger;
};

TEST_F(RpmAttributeTests, missing_epoch) {
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_EPOCH, td, logger), "");
  EXPECT_TRUE(logger.messages.empty());
}

TEST_F(RpmAttributeTests, present_epoch) {
  for (std::uint32_t epoch : {0U, 7U}) {
    headerDel(header, RPMTAG_EPOCH);
    ASSERT_EQ(headerPutUint32(header, RPMTAG_EPOCH, &epoch, 1), 1);
    EXPECT_EQ(getRpmAttribute(header, RPMTAG_EPOCH, td, logger),
              std::to_string(epoch));
  }
  EXPECT_TRUE(logger.messages.empty());
}

TEST_F(RpmAttributeTests, missing_name) {
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_NAME, td, logger), "");
  ASSERT_EQ(logger.messages.size(), 1U);
  EXPECT_EQ(logger.messages[0],
            "Could not get RPM header tag Name (1000) for package <unknown>");
}

TEST_F(RpmAttributeTests, missing_other_tag_and_container_state) {
  ASSERT_EQ(headerPutString(header, RPMTAG_NAME, "synthetic-package"), 1);
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_VERSION, td, logger), "");
  ASSERT_EQ(logger.messages.size(), 1U);
  EXPECT_EQ(logger.messages[0],
            "Could not get RPM header tag Version (1001) for package "
            "synthetic-package");
  // Diagnostic lookup must not replace the failed tag's container with Name.
  EXPECT_EQ(td->tag, RPMTAG_VERSION);
  EXPECT_EQ(td->data, nullptr);
  EXPECT_EQ(td->count, 0U);
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_NAME, td, logger),
            "synthetic-package");
  EXPECT_EQ(logger.messages.size(), 1U);
}

TEST_F(RpmAttributeTests, present_epoch_failed_retrieval) {
  std::uint32_t epoch{7};
  ASSERT_EQ(headerPutUint32(header, RPMTAG_EPOCH, &epoch, 1), 1);
  ASSERT_EQ(headerPutString(header, RPMTAG_NAME, "synthetic-package"), 1);
  ASSERT_EQ(headerIsEntry(header, RPMTAG_EPOCH), 1);
  // Real API failure, not a simulated corrupt package: headerGet rejects null td.
  rpmtd invalid_td{nullptr};
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_EPOCH, invalid_td, logger), "");
  ASSERT_EQ(logger.messages.size(), 1U);
  EXPECT_EQ(logger.messages[0],
            "Could not get RPM header tag Epoch (1003) for package "
            "synthetic-package");
}

TEST_F(RpmAttributeTests, invalid_container_missing_epoch) {
  rpmtd invalid_td{nullptr};
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_EPOCH, invalid_td, logger), "");
  ASSERT_EQ(logger.messages.size(), 1U);
  EXPECT_EQ(logger.messages[0],
            "Could not get RPM header tag Epoch (1003) for package <unknown>");
}

TEST_F(RpmAttributeTests, invalid_header) {
  Header invalid_header{nullptr};
  EXPECT_EQ(getRpmAttribute(invalid_header, RPMTAG_EPOCH, td, logger), "");
  ASSERT_EQ(logger.messages.size(), 1U);
  EXPECT_EQ(logger.messages[0],
            "Could not get RPM header tag Epoch (1003) for package <unknown>");
}

TEST_F(RpmAttributeTests, repeated_attributes) {
  ASSERT_EQ(headerPutString(header, RPMTAG_NAME, "synthetic-package"), 1);
  const std::vector<rpmTag> tags = {
      RPMTAG_NAME, RPMTAG_VERSION, RPMTAG_RELEASE, RPMTAG_SOURCERPM,
      RPMTAG_SIZE, RPMTAG_SHA1HEADER, RPMTAG_ARCH, RPMTAG_EPOCH,
      RPMTAG_INSTALLTIME, RPMTAG_VENDOR, RPMTAG_GROUP};
  // Three enumerations of 100 synthetic headers: nine failures per row.
  for (int query = 0; query < 3; ++query) {
    for (int package = 0; package < 100; ++package) {
      for (auto tag : tags) {
        EXPECT_EQ(getRpmAttribute(header, tag, td, logger),
                  tag == RPMTAG_NAME ? "synthetic-package" : "");
      }
    }
  }
  EXPECT_EQ(logger.messages.size(), 2700U);
}

TEST_F(RpmAttributeTests, malformed_insertion_is_not_retrieval_failure) {
  std::uint32_t invalid_name{7};
  EXPECT_EQ(headerPutUint32(header, RPMTAG_NAME, &invalid_name, 1), 0);
  EXPECT_EQ(headerIsEntry(header, RPMTAG_NAME), 0);
  EXPECT_EQ(getRpmAttribute(header, RPMTAG_NAME, td, logger), "");
  EXPECT_EQ(logger.messages.size(), 1U);
}
// END RPM ATTRIBUTE REGRESSIONS

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

namespace {

// Expand an RPM macro expression.
std::string expandRpmMacros(const std::string& expression) {
  auto expanded = rpmExpand(expression.c_str(), nullptr);
  std::string result = (expanded != nullptr) ? expanded : "";
  free(expanded);
  return result;
}

} // namespace

// %(...) shell command macros must never run a command, since osquery reads
// RPM configuration from untrusted sources such as containers.
TEST_F(RpmTests, test_shell_macros_do_not_run) {
  auto marker =
      boost::filesystem::temp_directory_path() /
      boost::filesystem::unique_path("osquery-rpm-shell-macro-%%%%%%%%");
  ASSERT_FALSE(boost::filesystem::exists(marker));
  const auto command = "%(touch " + marker.string() + ")";

  EXPECT_EQ(expandRpmMacros(command), "");
  EXPECT_FALSE(boost::filesystem::exists(marker));

  // Macros defined in a macros file are expanded when they are used.
  addMacro(nullptr, "osquery_test_shell", nullptr, command.c_str(), 0);
  EXPECT_EQ(expandRpmMacros("%{osquery_test_shell}"), "");
  delMacro(nullptr, "osquery_test_shell");
  EXPECT_FALSE(boost::filesystem::exists(marker));

  boost::system::error_code ec;
  boost::filesystem::remove(marker, ec);
}

// A disabled shell command macro expands to nothing, and the rest of the
// expression is still expanded.
TEST_F(RpmTests, test_shell_macros_keep_surrounding_text) {
  EXPECT_EQ(expandRpmMacros("/var/%(echo x)lib/rpm"), "/var/lib/rpm");

  addMacro(nullptr, "osquery_test_path", nullptr, "/var/%(echo x)lib/rpm", 0);
  EXPECT_EQ(expandRpmMacros("%{osquery_test_path}/Packages"),
            "/var/lib/rpm/Packages");
  delMacro(nullptr, "osquery_test_path");
}

} // namespace tables
} // namespace osquery
