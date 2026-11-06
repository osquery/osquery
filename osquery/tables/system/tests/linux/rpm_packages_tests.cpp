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
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/env.h>
#include <osquery/worker/logging/glog/glog_logger.h>

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

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

using namespace testing;

namespace osquery {
namespace tables {

QueryData genRpmPackages(QueryContext& context);
void genRpmPackageFiles(RowYield& yield, QueryContext& context);

rpmlogCallback gPreviousCallback{nullptr};

/**
 * librpm reads RPM_CONFIGDIR only once per process, so all tests in this
 * binary share the configuration directory of the first one to read it. Set
 * it up before any test runs, with the rpmrc that reading the configuration
 * requires. Each test still selects its database with the _dbpath macro.
 */
class RpmConfigEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    namespace fs = boost::filesystem;
    config_dir_ = fs::temp_directory_path() /
                  fs::unique_path("osquery-rpm-config-%%%%-%%%%");
    fs::create_directories(config_dir_);
    std::ofstream((config_dir_ / "rpmrc").string()).close();
    setEnvVar("RPM_CONFIGDIR", config_dir_.string());
    rpmConfigDir();
  }

  void TearDown() override {
    unsetEnvVar("RPM_CONFIGDIR");
    boost::filesystem::remove_all(config_dir_);
  }

 private:
  boost::filesystem::path config_dir_;
};

const auto* const kRpmConfigEnvironment =
    ::testing::AddGlobalTestEnvironment(new RpmConfigEnvironment);

class RpmTests : public ::testing::Test {
 public:
  static int Callback(rpmlogRec rec, rpmlogCallbackData data) {
    return 0;
  }

 protected:
  void SetUp() {
    // Dropping privileges, which the tests do when run as root, looks the
    // nobody user up through the users table.
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    gPreviousCallback = rpmlogSetCallback(&RpmTests::Callback, nullptr);
  }

  void setConfig(const std::string& path) {
    config_ = getEnvVar("RPM_CONFIGDIR");
    setEnvVar("RPM_CONFIGDIR", path);
    addMacro(nullptr, "_dbpath", nullptr, path.c_str(), 0);
    addMacro(nullptr, "rpmdb", nullptr, path.c_str(), 0);
  }

  // Copies the BDB fixture into a directory only its owner can access and
  // points librpm at it. Returns the new directory; the caller removes it.
  boost::filesystem::path useRootOnlyBdbDatabase() {
    namespace fs = boost::filesystem;
    auto source = fs::absolute(getTestConfigDirectory() / "rpm" / "rpm-bdb");
    auto db_dir =
        fs::temp_directory_path() / fs::unique_path("osquery-rpm-%%%%-%%%%");
    fs::create_directories(db_dir);
    for (const auto& entry : fs::directory_iterator(source)) {
      fs::copy_file(entry.path(), db_dir / entry.path().filename());
    }
    fs::permissions(db_dir, fs::owner_all);
    this->setConfig(db_dir.string());
    return db_dir;
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

// rpm_packages opens the database before dropping privileges, so it reads a
// database that only root can open, as when /var/lib/rpm is not readable by
// other users.
TEST_F(RpmTests, test_rpm_packages_reads_root_only_database) {
  if (!isUserAdmin()) {
    GTEST_SKIP() << "Creating a database only root can open requires root";
  }

  auto db_dir = useRootOnlyBdbDatabase();

  QueryContext context;
  auto results = genRpmPackages(context);
  boost::filesystem::remove_all(db_dir);

  std::vector<std::string> names;
  for (const auto& row : results) {
    names.push_back(row.at("name"));
  }
  std::vector<std::string> expected = {"rpm-libs", "rpm-python", "rpm"};
  EXPECT_EQ(expected, names);
}

// rpm_package_files has its own open/drop sequence: drive its coroutine
// against the same root-only database and check the files it yields.
TEST_F(RpmTests, test_rpm_package_files_reads_root_only_database) {
  if (!isUserAdmin()) {
    GTEST_SKIP() << "Creating a database only root can open requires root";
  }

  auto db_dir = useRootOnlyBdbDatabase();

  QueryContext context;
  RowGenerator::pull_type rows(
      [&context](RowYield& yield) { genRpmPackageFiles(yield, context); });
  std::map<std::string, std::vector<std::string>> files;
  for (const auto& row : rows) {
    Row r = static_cast<Row>(*row);
    files[r.at("package")].push_back(r.at("path"));
  }
  boost::filesystem::remove_all(db_dir);

  std::vector<std::string> expected_rpm_libs = {
      "/usr/lib64/librpm.so.1",
      "/usr/lib64/librpm.so.1.0.0",
      "/usr/lib64/librpmbuild.so.1",
      "/usr/lib64/librpmbuild.so.1.0.0",
      "/usr/lib64/librpmio.so.1",
      "/usr/lib64/librpmio.so.1.0.0",
  };
  EXPECT_EQ(expected_rpm_libs, files["rpm-libs"]);

  std::vector<std::string> expected_rpm_python = {
      "/usr/lib64/python2.6/site-packages/rpm",
      "/usr/lib64/python2.6/site-packages/rpm/__init__.py",
      "/usr/lib64/python2.6/site-packages/rpm/__init__.pyc",
      "/usr/lib64/python2.6/site-packages/rpm/__init__.pyo",
      "/usr/lib64/python2.6/site-packages/rpm/_rpmbmodule.so",
      "/usr/lib64/python2.6/site-packages/rpm/_rpmmodule.so",
      "/usr/lib64/python2.6/site-packages/rpm/transaction.py",
      "/usr/lib64/python2.6/site-packages/rpm/transaction.pyc",
      "/usr/lib64/python2.6/site-packages/rpm/transaction.pyo",
  };
  EXPECT_EQ(expected_rpm_python, files["rpm-python"]);

  // The rpm package's 140 files are too many to list; check the count and a
  // few paths spanning the package.
  const auto& rpm_files = files["rpm"];
  EXPECT_EQ(140U, rpm_files.size());
  for (const auto* path : {"/bin/rpm",
                           "/usr/lib/rpm/rpmrc",
                           "/usr/share/locale/sv/LC_MESSAGES/rpm.mo",
                           "/var/lib/rpm/Packages"}) {
    EXPECT_NE(rpm_files.end(),
              std::find(rpm_files.begin(), rpm_files.end(), path));
  }
}

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
