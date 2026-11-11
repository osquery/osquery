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
  auto rows = execute_query("select * from rpm_packages");
  if (rows.empty()) {
    LOG(WARNING) << "Empty results of query from 'rpm_packages', assume there "
                    "is no rpm on the system";
    return;
  }

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
    validate_container_rows("rpm_packages", row_map);
  }
}

// Regression test for the generator self-deadlock: rpm_package_files holds the
// recursive librpm mutex across its yield()s, so a CROSS JOIN (which pins it as
// the outer scan) runs rpm_packages on the same thread while it's suspended. A
// non-recursive mutex deadlocks here; it must re-enter and complete instead.
// Pointed at a checked-in rpmdb fixture so it runs on Ubuntu CI, which has no
// system rpmdb.
class rpmPackageFilesDeadlock : public testing::Test {
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
} // namespace table_tests
} // namespace osquery
