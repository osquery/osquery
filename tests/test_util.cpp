/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <deque>
#include <random>
#include <sstream>
#include <thread>

#include <csignal>
#include <ctime>

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>

#include <osquery/core/system.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>

#include <osquery/process/process.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/info/platform_type.h>

#ifdef OSQUERY_WINDOWS
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#include <osquery/system/usersgroups/windows/users_service.h>
#endif

namespace fs = boost::filesystem;

namespace osquery {

/// Will be set with initTesting in test harness main.
std::string kFakeDirectory;

/// Will be set with initTesting in test harness main.
std::string kTestWorkingDirectory;

/// The relative path within the source repo to find test content.
std::string kTestDataPath{"../../../tools/tests/"};

DECLARE_string(database_path);
DECLARE_string(extensions_socket);
DECLARE_string(extensions_autoload);
DECLARE_string(enroll_tls_endpoint);
DECLARE_bool(disable_logging);

using chrono_clock = std::chrono::high_resolution_clock;

void initTesting() {
  setStartTime(getUnixTime());

  setToolType(ToolType::TEST);
  if (osquery::isPlatform(PlatformType::TYPE_OSX)) {
    kTestWorkingDirectory = "/private/tmp/osquery-tests";
  } else {
    kTestWorkingDirectory =
        (fs::temp_directory_path() / "osquery-tests").string();
  }

  if (osquery::isPlatform(PlatformType::TYPE_WINDOWS)) {
    kTestDataPath = "../" + kTestDataPath;
  }

  // Allow unit test execution from anywhere in the osquery source/build tree.
  if (fs::exists("test_data/test_inline_pack.conf")) {
    // If the execution occurs within the build/shared directory and shared
    // is pointing to a tmp build directory. See #3414.
    kTestDataPath = "test_data/";
  } else if (fs::exists("../test_data/test_inline_pack.conf")) {
    // ctest executes from the osquery subdirectory. If this is a build/shared
    // link then the test_data directory links to the source repo.
    kTestDataPath = "../test_data/";
  } else {
    while (kTestDataPath.find("tools") != 0) {
      if (!fs::exists(kTestDataPath + "test_inline_pack.conf")) {
        kTestDataPath = kTestDataPath.substr(3, kTestDataPath.size());
      } else {
        break;
      }
    }
  }

  // The tests will fail randomly without test data.
  if (!fs::exists(kTestDataPath)) {
    throw std::runtime_error("Cannot find test data path");
  }

  // Seed the random number generator, some tests generate temporary files
  // ports, sockets, etc using random numbers.
  std::srand(static_cast<unsigned int>(
      chrono_clock::now().time_since_epoch().count()));

  // Set safe default values for path-based flags.
  // Specific unittests may edit flags temporarily.
  kTestWorkingDirectory += std::to_string(platformGetUid()) + "/";
  kFakeDirectory = kTestWorkingDirectory + kFakeDirectoryName;

  fs::remove_all(kTestWorkingDirectory);
  fs::create_directories(kTestWorkingDirectory);
  FLAGS_database_path = kTestWorkingDirectory + "unittests.db";
  FLAGS_extensions_socket = kTestWorkingDirectory + "unittests.em";
  FLAGS_extensions_autoload = kTestWorkingDirectory + "unittests-ext.load";

  FLAGS_disable_logging = true;

  platformSetup();
  registryAndPluginInit();
  initDatabasePluginForTesting();
}

void shutdownTesting() {
  shutdownDatabase();
  platformTeardown();
}

#ifdef OSQUERY_WINDOWS
void initUsersAndGroupsServices(bool init_users, bool init_groups) {
  if (init_users) {
    std::promise<void> users_cache_promise;
    GlobalUsersGroupsCache::global_users_cache_future_ =
        users_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<UsersService>(
        std::move(users_cache_promise),
        GlobalUsersGroupsCache::global_users_cache_));
  }

  if (init_groups) {
    std::promise<void> groups_cache_promise;
    GlobalUsersGroupsCache::global_groups_cache_future_ =
        groups_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<GroupsService>(
        std::move(groups_cache_promise),
        GlobalUsersGroupsCache::global_groups_cache_));
  }
}

void deinitUsersAndGroupsServices(bool deinit_users, bool deinit_groups) {
  if (deinit_users) {
    GlobalUsersGroupsCache::global_users_cache_->clear();
    GlobalUsersGroupsCache::global_users_cache_future_ = {};
  }
  if (deinit_groups) {
    GlobalUsersGroupsCache::global_groups_cache_->clear();
    GlobalUsersGroupsCache::global_groups_cache_future_ = {};
  }
}
#endif

ScheduledQuery getOsqueryScheduledQuery() {
  ScheduledQuery sq(
      "path_pack",
      "bin",
      "SELECT filename FROM fs WHERE path = '/bin' ORDER BY filename");

  sq.interval = 5;

  return sq;
}

TableRows genRows(EventSubscriberPlugin* sub) {
  auto vtc = std::make_shared<VirtualTableContent>();
  QueryContext context(vtc);
  RowGenerator::pull_type generator(std::bind(&EventSubscriberPlugin::genTable,
                                              sub,
                                              std::placeholders::_1,
                                              std::move(context)));

  TableRows results;
  if (!generator) {
    return results;
  }

  while (generator) {
    results.push_back(generator.get());
    generator();
  }
  return results;
}

} // namespace osquery
