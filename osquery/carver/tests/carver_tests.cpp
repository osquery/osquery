/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <gtest/gtest.h>

#include <osquery/carver/carver.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/database.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/hashing/hashing.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/utils/json.h>

namespace osquery {

namespace fs = boost::filesystem;

DECLARE_bool(disable_database);

/// Prefix used for posix tar archive.
const std::string kTestCarveNamePrefix = "carve_";

std::string genGuid() {
  return boost::uuids::to_string(boost::uuids::random_generator()());
};

class CarverTests : public testing::Test {
 public:
  CarverTests() {
    fs::create_directories(fs::temp_directory_path() / "files_to_carve/");
    writeTextFile(fs::temp_directory_path() / "files_to_carve/secrets.txt",
                  "This is a message I'd rather no one saw.");
    writeTextFile(fs::temp_directory_path() / "files_to_carve/evil.exe",
                  "MZP\x00\x02\x00\x00\x00\x04\x00\x0f\x00\xff\xff");

    auto paths =
        platformGlob((fs::temp_directory_path() / "files_to_carve/*").string());
    for (const auto& p : paths) {
      carvePaths.insert(p);
    }
  }

  std::set<std::string>& getCarvePaths() {
    return carvePaths;
  }

 protected:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();

    // Force registry to use ephemeral database plugin
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
  }
  void TearDown() override {
    fs::remove_all(fs::temp_directory_path() / "/files_to_carve/");
  }

 private:
  std::set<std::string> carvePaths;
};

TEST_F(CarverTests, test_carve_files_locally) {
  auto guid_ = genGuid();
  auto paths_ = getCarvePaths();
  std::string requestId = "";
  Carver carve(getCarvePaths(), guid_, requestId);

  Status s;
  for (const auto& p : paths_) {
    s = carve.carve(fs::path(p));
    EXPECT_TRUE(s.ok());
  }

  std::string carveFSPath = carve.getCarveDir().string();
  auto paths = platformGlob(carveFSPath + "/*");
  std::set<fs::path> carves;
  for (const auto& p : paths) {
    carves.insert(fs::path(p));
  }

  EXPECT_EQ(carves.size(), 2U);
  s = archive(carves,
              carveFSPath + "/" + kTestCarveNamePrefix + guid_ + ".tar");
  EXPECT_TRUE(s.ok());

  auto tarPath = carveFSPath + "/" + kTestCarveNamePrefix + guid_ + ".tar";
  PlatformFile tar(tarPath, PF_OPEN_EXISTING | PF_READ);
  EXPECT_TRUE(tar.isValid());
  EXPECT_GT(tar.size(), 0U);
}

TEST_F(CarverTests, test_compression) {
  auto s = osquery::compress(getTestConfigDirectory() / "test.config",
                             fs::temp_directory_path() / fs::path("test.zst"));
  EXPECT_TRUE(s.ok());
}

TEST_F(CarverTests, test_decompression) {
  std::cout << fs::temp_directory_path() << "\n";
  std::cout << (getTestConfigDirectory() / "test.config") << "\n";
  auto s = osquery::decompress(
      fs::temp_directory_path() / fs::path("test.zst"),
      fs::temp_directory_path() / fs::path("test.config.extract"));
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(
      hashFromFile(HashType::HASH_TYPE_SHA256,
                   (fs::temp_directory_path() / fs::path("test.config.extract"))
                       .string()),
      hashFromFile(
          HashType::HASH_TYPE_SHA256,
          (getTestConfigDirectory() / fs::path("test.config")).string()));
}
} // namespace osquery
