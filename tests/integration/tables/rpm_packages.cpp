/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for rpm_packages
// Spec file: specs/linux/rpm_packages.table

#include <osquery/logger/logger.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/system/env.h>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <future>
#include <set>
#include <thread>
#include <utility>

namespace osquery {
namespace table_tests {

class rpmPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(rpmPackages, test_sanity) {
  // rpmdbs can contain pseudo-packages (e.g. gpg-pubkey entries, one per
  // imported GPG key) that have no vendor, arch, or epoch and so cannot pass
  // the validation below. Rather than excluding them by name, select only
  // rows that satisfy the invariant being validated (CI has no rpmdb and
  // never sees any of this).
  auto rows = execute_query(
      "select * from rpm_packages where vendor != '' and arch != ''");
  if (rows.empty()) {
    LOG(WARNING) << "Empty results of query from 'rpm_packages', assume there "
                    "is no rpm on the system";
    return;
  }

  // Any real rpm install has more than a handful of proper packages; fewer
  // would mean the filter (or the table's vendor/arch parsing) is broken,
  // not that the system is minimal.
  ASSERT_GE(rows.size(), 5u);

  ValidationMap row_map = {{"name", NonEmptyString},
                           {"version", NormalType},
                           {"release", NormalType},
                           {"source", NormalType},
                           {"size", IntType},
                           {"sha1", NonEmptyString},
                           {"arch", NonEmptyString},
                           {"epoch", IntOrEmpty},
                           {"install_time", IntType},
                           {"vendor", NonEmptyString},
                           {"package_group", NonEmptyString}};

  validate_rows(rows, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows(
        "rpm_packages", row_map, "vendor != '' and arch != ''");
  }
}

// Base fixture that points librpm at the checked-in rpm-sqlite rpmdb via a
// private ~/.rpmmacros, giving these tests a deterministic package set on CI
// hosts that have no system rpmdb.
class rpmSqliteFixture : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    // TEST_CONF_FILES_DIR is injected by ctest; skip a direct binary run.
    auto conf_dir = getEnvVar("TEST_CONF_FILES_DIR");
    if (!conf_dir) {
      GTEST_SKIP() << "TEST_CONF_FILES_DIR not set; run via ctest";
    }

    if (!boost::filesystem::exists("/usr/lib/rpm/rpmrc")) {
      GTEST_SKIP() << "system rpm config (/usr/lib/rpm/rpmrc) not present";
    }
    auto fixture = boost::filesystem::absolute(
        boost::filesystem::path(*conf_dir) / "rpm" / "rpm-sqlite");

    // Point librpm at the checked-in fixture via ~/.rpmmacros. rpm re-reads it
    // on every rpmReadConfigFiles, and the generators' RpmSession frees the
    // macro context after each query, so a macro written here survives across
    // the guard and join queries -- a one-shot addMacro would be wiped between
    // them. HOME (not RPM_CONFIGDIR) so the generator still loads the full
    // system config from /usr/lib/rpm and only _dbpath is overridden.
    home_dir_ = boost::filesystem::temp_directory_path() /
                boost::filesystem::unique_path("osquery-rpmhome-%%%%%%%%");
    boost::filesystem::create_directories(home_dir_);
    {
      std::ofstream rpmmacros((home_dir_ / ".rpmmacros").string());
      rpmmacros << "%_dbpath " << fixture.string() << "\n%_db_backend sqlite\n";
    }

    saved_home_ = getEnvVar("HOME");
    setEnvVar("HOME", home_dir_.string());
    setup_done_ = true;
  }

  void TearDown() override {
    // saved_home_ is set only after the skip guards above, so a skipped SetUp
    // must not restore/unset HOME (googletest still runs TearDown after a
    // skip).
    if (!setup_done_) {
      return;
    }
    if (saved_home_) {
      setEnvVar("HOME", *saved_home_);
    } else {
      unsetEnvVar("HOME");
    }
    if (!home_dir_.empty()) {
      boost::system::error_code ec;
      boost::filesystem::remove_all(home_dir_, ec);
    }
  }

 private:
  boost::filesystem::path home_dir_;
  boost::optional<std::string> saved_home_;
  bool setup_done_{false};
};

// Regression test for the generator self-deadlock: rpm_package_files holds the
// recursive librpm mutex across its yield()s, so a CROSS JOIN (which pins it as
// the outer scan) runs rpm_packages on the same thread while it's suspended. A
// non-recursive mutex deadlocks here; it must re-enter and complete instead.
class rpmPackageFilesDeadlock : public rpmSqliteFixture {};

TEST_F(rpmPackageFilesDeadlock, files_join_packages_completes) {
  // Guard against a vacuous pass: an empty table makes the join trivial.
  ASSERT_FALSE(execute_query("select 1 from rpm_package_files limit 1").empty())
      << "rpm-sqlite fixture produced no rpm_package_files rows";

  // Run off-thread so a regression surfaces as a timeout, not a hung binary.
  std::packaged_task<std::pair<Status, std::size_t>()> query([] {
    auto instance = SQLiteDBManager::get();
    QueryDataTyped rows;
    auto status = queryInternal(
        "select f.path from rpm_package_files f "
        "cross join rpm_packages p limit 1",
        rows,
        instance);
    return std::make_pair(status, rows.size());
  });
  auto done = query.get_future();
  std::thread worker(std::move(query));

  if (done.wait_for(std::chrono::seconds(60)) == std::future_status::timeout) {
    // The wedged thread still holds RpmSession's recursive mutex; every later
    // rpm query in this binary (gtest cross-TU order is unspecified) would
    // block on it. Take the process down rather than hang the ctest run.
    ADD_FAILURE() << "rpm_package_files/rpm_packages join deadlocked";
    worker.detach();
    std::_Exit(1);
  }
  worker.join();

  auto result = done.get();
  EXPECT_TRUE(result.first.ok());
  // A zero-row join never opens the inner cursor, so the re-entry goes
  // untested.
  EXPECT_GT(result.second, 0u)
      << "join returned no rows; the nested rpm_packages scan was never driven";
}

// Fixture-backed coverage for the indexed per-value constraint path: a single
// equality and a multi-value IN must return exactly the matching rows -- each
// present value once (no duplicate from the per-value loop) and absent values
// dropped (no leakage, no missing).
class rpmPackagesConstraints : public rpmSqliteFixture {};

TEST_F(rpmPackagesConstraints, name_equals_returns_only_match) {
  auto rows = execute_query(
      "select name, version from rpm_packages where name = 'rpm'");
  ASSERT_EQ(rows.size(), 1u);
  EXPECT_EQ(rows[0].at("name"), "rpm");
  EXPECT_EQ(rows[0].at("version"), "4.16.0");
}

TEST_F(rpmPackagesConstraints, name_in_list_returns_each_present_value_once) {
  auto rows = execute_query(
      "select name from rpm_packages "
      "where name in ('rpm', 'deltarpm', 'osquery-absent')");
  std::multiset<std::string> names;
  for (const auto& r : rows) {
    names.insert(r.at("name"));
  }
  // Both present values appear exactly once; the absent value is dropped.
  EXPECT_EQ(names, (std::multiset<std::string>{"deltarpm", "rpm"}));
}

TEST_F(rpmPackagesConstraints, package_files_in_honors_constraint) {
  // Pick a package that actually has files in the fixture rather than assume.
  auto any = execute_query("select package from rpm_package_files limit 1");
  ASSERT_FALSE(any.empty());
  auto package = any[0].at("package");

  auto rows = execute_query(
      "select distinct package from rpm_package_files "
      "where package in ('" +
      package + "', 'osquery-absent')");
  std::set<std::string> packages;
  for (const auto& r : rows) {
    packages.insert(r.at("package"));
  }
  EXPECT_EQ(packages, (std::set<std::string>{package}));
}
} // namespace table_tests
} // namespace osquery
