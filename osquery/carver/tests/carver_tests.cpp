/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/carver/carver.h>
#include <osquery/carver/carver_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/hashing/hashing.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/json/json.h>

namespace osquery {

namespace fs = boost::filesystem;

/// Prefix used for posix tar archive.
const std::string kTestCarveNamePrefix = "carve_";

class FakeCarver : public Carver {
 public:
  FakeCarver(const std::set<std::string>& paths,
             const std::string& guid,
             const std::string& requestId)
      : Carver(paths, guid, requestId) {}

 protected:
  Status postCarve(const boost::filesystem::path&) override {
    updateCarveValue(carveGuid_, "status", kCarverStatusSuccess);
    return Status::success();
  }

 private:
  friend class CarverTests;
  FRIEND_TEST(CarverTests, test_carve_files_locally);
  FRIEND_TEST(CarverTests, test_carve_start);
  FRIEND_TEST(CarverTests, test_carve_files_not_exists);
};

class FakeCarverRunner : public CarverRunner<FakeCarver> {
 public:
  FakeCarverRunner() : CarverRunner() {}
};

class CarverTests : public testing::Test {
 public:
  std::set<std::string>& getCarvePaths() {
    return carvePaths;
  }

  fs::path const& getWorkingDir() const {
    return working_dir_;
  }

  fs::path const& getFilesToCarveDir() const {
    return files_to_carve_dir_;
  }

 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    working_dir_ =
        fs::temp_directory_path() /
        fs::unique_path("osquery.carver_tests.working_dir.%%%%.%%%%");
    fs::create_directories(working_dir_);

    files_to_carve_dir_ = working_dir_ / "files_to_carve";
    fs::create_directories(files_to_carve_dir_);

    writeTextFile(files_to_carve_dir_ / "secrets.txt",
                  "This is a message I'd rather no one saw.");
    writeTextFile(files_to_carve_dir_ / "evil.exe",
                  "MZP\x00\x02\x00\x00\x00\x04\x00\x0f\x00\xff\xff");

    writeTextFileToCarve(files_to_carve_dir_ / "secrets.txt",
                         "This is a message I'd rather no one saw.");
    writeTextFileToCarve(files_to_carve_dir_ / ".hidden.bashrc",
                         "This is a hidden file");
    writeTextFileToCarve(files_to_carve_dir_ / "evil.exe",
                         "MZP\x00\x02\x00\x00\x00\x04\x00\x0f\x00\xff\xff");
  }

  void writeTextFileToCarve(const fs::path& path, const std::string& content) {
    EXPECT_TRUE(writeTextFile(path, content).ok());
    carvePaths.insert(path.string());
  }

  void TearDown() override {
    fs::remove_all(files_to_carve_dir_);
    fs::remove_all(working_dir_);
  }

 private:
  fs::path working_dir_;
  fs::path files_to_carve_dir_;
  std::set<std::string> carvePaths;
};

TEST_F(CarverTests, test_carve_files_locally) {
  auto guid = createCarveGuid();
  std::string requestId = createCarveGuid();
  FakeCarver carve(getCarvePaths(), guid, requestId);

  ASSERT_TRUE(carve.createPaths());
  const auto carves = carve.carveAll();
  EXPECT_EQ(carves.size(), 3U);

  const auto carveFSPath = carve.getCarveDir();
  const auto tarPath = carveFSPath / (kTestCarveNamePrefix + guid + ".tar");
  const auto s = archive(carves, tarPath);
  EXPECT_TRUE(s.ok());

  PlatformFile tar(tarPath, PF_OPEN_EXISTING | PF_READ);
  EXPECT_TRUE(tar.isValid());
  EXPECT_GT(tar.size(), 0U);
}

TEST_F(CarverTests, test_carve) {
  auto guid = createCarveGuid();
  std::string requestId = createCarveGuid();
  FakeCarver carve(getCarvePaths(), guid, requestId);
  auto s = carve.carve();
  ASSERT_TRUE(s.ok());
}

TEST_F(CarverTests, test_schedule_carves) {
  // Request paths for carving.
  std::string new_carve_guid;
  auto s = osquery::carvePaths(getCarvePaths(), "request-id", new_carve_guid);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(new_carve_guid.empty());

  ASSERT_FALSE(FakeCarverRunner::running());
  {
    FakeCarverRunner runner;
    ASSERT_TRUE(FakeCarverRunner::running());
    runner.start();

    EXPECT_EQ(runner.carves(), 1);
  }

  {
    FakeCarverRunner runner;
    ASSERT_TRUE(FakeCarverRunner::running());
    runner.start();

    // All carves were previously completed.
    EXPECT_EQ(runner.carves(), 0);
  }

  ASSERT_FALSE(FakeCarverRunner::running());
}

TEST_F(CarverTests, test_expiration) {
  {
    // Reset the carves.
    std::vector<std::string> carves;
    scanDatabaseKeys(kCarves, carves, kCarverDBPrefix);
    for (const auto& key : carves) {
      deleteDatabaseValue(kCarves, key);
    }
  }

  // Create 2 carve requests.
  std::string first_carve_guid;
  auto s = osquery::carvePaths(getCarvePaths(), "request-id", first_carve_guid);
  ASSERT_TRUE(s.ok());

  std::string second_carve_guid;
  s = osquery::carvePaths(getCarvePaths(), "request-id", second_carve_guid);
  ASSERT_TRUE(s.ok());
  EXPECT_NE(first_carve_guid, second_carve_guid);

  {
    // Set one request to an expired time.
    std::vector<std::string> carves;
    scanDatabaseKeys(kCarves, carves, kCarverDBPrefix);
    EXPECT_EQ(carves.size(), 2);

    std::string carve;
    s = getDatabaseValue(kCarves, carves[0], carve);
    ASSERT_TRUE(s.ok());

    JSON tree;
    s = tree.fromString(carve);
    ASSERT_TRUE(s.ok());

    std::string guid(tree.doc()["carve_guid"].GetString());
    EXPECT_FALSE(guid.empty());
    std::string request_id(tree.doc()["request_id"].GetString());
    EXPECT_EQ(request_id, "request-id");

    tree.add("time", 0);
    tree.add("status", kCarverStatusSuccess);
    s = tree.toString(carve);
    ASSERT_TRUE(s.ok());
    s = setDatabaseValue(kCarves, carves[0], carve);
    ASSERT_TRUE(s.ok());
  }

  {
    // Schedule the carves and expect the expired successful carve to be
    // deleted.
    FakeCarverRunner runner;
    runner.start();
    EXPECT_EQ(runner.carves(), 1);

    std::vector<std::string> carves;
    scanDatabaseKeys(kCarves, carves, kCarverDBPrefix);
    EXPECT_EQ(carves.size(), 1);

    std::string carve;
    s = getDatabaseValue(kCarves, carves[0], carve);
    ASSERT_TRUE(s.ok());

    JSON tree;
    s = tree.fromString(carve);
    ASSERT_TRUE(s.ok());

    std::string guid(tree.doc()["carve_guid"].GetString());
    EXPECT_FALSE(guid.empty());

    // This time only update the time.
    // Expect the carve to have been successful.
    tree.add("time", 0);
    s = tree.toString(carve);
    ASSERT_TRUE(s.ok());
    s = setDatabaseValue(kCarves, carves[0], carve);
    ASSERT_TRUE(s.ok());
  }

  {
    FakeCarverRunner runner;
    runner.start();
    EXPECT_EQ(runner.carves(), 0);

    std::vector<std::string> carves;
    scanDatabaseKeys(kCarves, carves, kCarverDBPrefix);
    EXPECT_TRUE(carves.empty());
  }
}

TEST_F(CarverTests, test_carve_files_not_exists) {
  auto guid = createCarveGuid();
  std::string requestId = "";
  const std::set<std::string> notExistsCarvePaths = {
      (getFilesToCarveDir() / "not_exists").string()};
  FakeCarver carve(notExistsCarvePaths, guid, requestId);
  const auto carves = carve.carveAll();
  EXPECT_TRUE(carves.empty());
}

TEST_F(CarverTests, test_compression_decompression) {
  auto const test_data_file = getWorkingDir() / "test.data";
  writeTextFile(test_data_file, R"raw_text(
2TItVMSvAY8OFlbYnx1O1NSsuehfNhNiV4Qw4IPP6exA47HVzAlEXZI3blanlAd2
JSxCUr+3boxWMwsgW2jJPzypSKvfXB9EDbFKiDjVueniBfiAepwta57pZ9tQDnJA
uRioApcqYSWL14OJrnPQFHel5FpXylmVdIkiz()cT82JsOPZmh56vDn62Kk/mU7V
RltGAYEpKmi8e71fuB8d/S6Lau{}AmL1153X7E+4d1G1UfiQa7Q02uVjxLLE5FEj
JTDjVqIQNhi50Pt4J4RVopYzy1AZGwPHLhwFVIPH0s/LmzVW+xbT8/V2UMSzK4XB
oqADd9Ckcdtplx3k7bcLU[U04j8WWUtUccmB+4e2KS]i3x7WDKviPY/sWy9xFapv
)raw_text");
  {
    auto s = osquery::compress(test_data_file,
                               getWorkingDir() / fs::path("test.zst"));
    ASSERT_TRUE(s.ok()) << s.what();
  }
  {
    auto s =
        osquery::decompress(getWorkingDir() / fs::path("test.zst"),
                            getWorkingDir() / fs::path("test.data.extract"));
    ASSERT_TRUE(s.ok()) << s.what();
  }

  EXPECT_EQ(
      hashFromFile(HashType::HASH_TYPE_SHA256,
                   (getWorkingDir() / fs::path("test.data.extract")).string()),
      hashFromFile(HashType::HASH_TYPE_SHA256, test_data_file.string()));
}
} // namespace osquery
