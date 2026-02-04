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
#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/hashing/hashing.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/base64.h>
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
    setDatabaseValue(kPersistentSettings, "nodeKey", "test_node_key");

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

    tree.addCopy("time", 0);
    tree.addCopy("status", kCarverStatusSuccess);
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
    tree.addCopy("time", 0);
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

TEST_F(CarverTests, test_carve_size_over_2gb_serialization) {
  // Carve metadata with sizes >2GB should be correctly
  // serialized and deserialized from the database.
  // - With the fix (properly converting BIGINT): Test passes
  // - Without the fix (only IsInt): Test will SEGFAULT

  std::vector<uint64_t> test_sizes = {
      0, // Zero
      1024, // 1KB
      2147483647, // Max int32 (2GB - 1)
      2147483648, // Min value that overflows int32 (exactly 2GB)
      2684354560, // 2.5GB
      4294967295, // Max uint32
      4294967296, // Max uint32 + 1
      8589934592 // 8GB
  };

  for (auto test_size : test_sizes) {
    auto guid = createCarveGuid();
    std::string requestId = createCarveGuid();

    // Create a carve entry with the test size
    JSON carve_doc;
    carve_doc.addCopy("carve_guid", guid);
    carve_doc.addCopy("request_id", requestId);
    carve_doc.addCopy("path", "/tmp/test_file_" + std::to_string(test_size));
    carve_doc.addCopy("status", "SUCCESS");
    carve_doc.addCopy("time", static_cast<uint64_t>(1234567890));
    carve_doc.addCopy("size", test_size);
    carve_doc.addCopy("sha256", "abc123");

    std::string serialized;
    auto s = carve_doc.toString(serialized);
    ASSERT_TRUE(s.ok()) << "Failed to serialize size: " << test_size;

    JSON verify_doc;
    s = verify_doc.fromString(serialized);
    ASSERT_TRUE(s.ok()) << "Failed to parse serialized JSON for size: "
                        << test_size;
    ASSERT_TRUE(verify_doc.doc().HasMember("size"))
        << "Serialized JSON missing size field for: " << test_size;

    // Write to database
    std::string key = kCarverDBPrefix + guid;
    s = setDatabaseValue(kCarves, key, serialized);
    ASSERT_TRUE(s.ok()) << "Failed to write to database for size: "
                        << test_size;

    // Query the carves table
    auto results =
        SQL::selectAllFrom("carves",
                           "path",
                           EQUALS,
                           "/tmp/test_file_" + std::to_string(test_size));

    ASSERT_EQ(results.size(), 1) << "Expected 1 carve result for size "
                                 << test_size << ", got " << results.size();

    // Verify the size field is correct
    auto& row = results[0];
    ASSERT_TRUE(row.count("size") > 0)
        << "Size field missing in result for test size: " << test_size;

    // Convert the size back to uint64_t and verify it matches
    uint64_t retrieved_size = std::stoull(row["size"]);
    EXPECT_EQ(retrieved_size, test_size)
        << "Size mismatch: expected " << test_size << ", got "
        << retrieved_size;

    deleteDatabaseValue(kCarves, key);
  }
}

class TransientFailureCarver : public Carver {
 public:
  TransientFailureCarver(const std::set<std::string>& paths,
                         const std::string& guid,
                         const std::string& requestId,
                         const std::set<size_t>& fail_on)
      : Carver(paths, guid, requestId), fail_on_(fail_on), call_count_(0) {}

  Status sendRequest(Request<TLSTransport, JSONSerializer>& request,
                     const JSON& params,
                     JSON& response) override {
    call_count_++;
    std::string body;
    params.toString(body);
    request_bodies_.push_back(std::move(body));

    if (fail_on_.count(call_count_)) {
      return Status::failure("Transient failure");
    }

    if (params.doc().HasMember("carve_id")) {
      response.add("session_id", "test_session");
    }

    return Status::success();
  }

  size_t call_count() const {
    return call_count_;
  }

  const std::vector<std::string>& request_bodies() const {
    return request_bodies_;
  }

 private:
  std::set<size_t> fail_on_;
  size_t call_count_;
  std::vector<std::string> request_bodies_;
};

TEST_F(CarverTests, test_carve_retries) {
  auto guid = createCarveGuid();
  std::string requestId = createCarveGuid();

  // Test success after specific failures.
  // Fail start requests 1 and 2, succeed at 3.
  // Fail block request 4, succeed at 5.
  TransientFailureCarver carve(getCarvePaths(), guid, requestId, {1, 2, 4});

  auto s = carve.carve();
  EXPECT_TRUE(s.ok()) << s.getMessage();

  const auto& bodies = carve.request_bodies();
  // 3 start requests (att 1, 2, 3) + 2 block requests (att 1, 2)
  ASSERT_GE(bodies.size(), 5U);

  uint64_t expected_carve_size = 0;
  // The first three requests should be 'start' requests (2 failed, 1
  // succeeded).
  for (size_t i = 0; i < 3; ++i) {
    JSON doc;
    ASSERT_TRUE(doc.fromString(bodies[i]).ok());
    EXPECT_EQ(std::string(doc.doc()["carve_id"].GetString()), guid);
    EXPECT_EQ(std::string(doc.doc()["request_id"].GetString()), requestId);
    EXPECT_EQ(std::string(doc.doc()["node_key"].GetString()), "test_node_key");
    EXPECT_TRUE(doc.doc().HasMember("block_count"));
    expected_carve_size = doc.doc()["carve_size"].GetUint64();
  }

  // The 4th and 5th requests should be for the first block (1 failed, 1
  // succeeded).
  for (size_t i = 3; i < 5; ++i) {
    JSON doc;
    ASSERT_TRUE(doc.fromString(bodies[i]).ok());
    EXPECT_EQ(std::string(doc.doc()["session_id"].GetString()), "test_session");
    EXPECT_EQ(std::string(doc.doc()["request_id"].GetString()), requestId);
    EXPECT_EQ(doc.doc()["block_id"].GetUint(), 0U);
    ASSERT_TRUE(doc.doc().HasMember("data"));

    std::string encoded_data = doc.doc()["data"].GetString();
    std::string decoded_data = base64::decode(encoded_data);
    EXPECT_EQ(decoded_data.size(), expected_carve_size);
  }

  EXPECT_EQ(carve.call_count(), 5U);
}

TEST_F(CarverTests, test_carve_start_failure) {
  auto guid = createCarveGuid();
  std::string requestId = createCarveGuid();

  // Test permanent failure (3 failures on start request).
  TransientFailureCarver carve(getCarvePaths(), guid, requestId, {1, 2, 3});

  auto s = carve.carve();
  EXPECT_FALSE(s.ok());
  EXPECT_EQ(carve.call_count(), 3U);

  const auto& bodies = carve.request_bodies();
  ASSERT_EQ(bodies.size(), 3U);
  for (const auto& body : bodies) {
    JSON doc;
    ASSERT_TRUE(doc.fromString(body).ok());
    EXPECT_EQ(std::string(doc.doc()["carve_id"].GetString()), guid);
    EXPECT_EQ(std::string(doc.doc()["request_id"].GetString()), requestId);
    EXPECT_TRUE(doc.doc().HasMember("carve_size"));
    EXPECT_GT(doc.doc()["carve_size"].GetUint64(), 0U);
  }
}

TEST_F(CarverTests, test_carve_block_failure) {
  auto guid = createCarveGuid();
  std::string requestId = createCarveGuid();

  // Test permanent failure on block send (Call 1 succeeds, Calls 2, 3, 4 fail).
  TransientFailureCarver carve(getCarvePaths(), guid, requestId, {2, 3, 4});

  auto s = carve.carve();
  EXPECT_FALSE(s.ok());
  // 1 success for start + 3 failures for block 0
  EXPECT_EQ(carve.call_count(), 4U);

  const auto& bodies = carve.request_bodies();
  ASSERT_EQ(bodies.size(), 4U);

  // Call 1 is start
  {
    JSON doc;
    ASSERT_TRUE(doc.fromString(bodies[0]).ok());
    EXPECT_TRUE(doc.doc().HasMember("carve_id"));
  }

  // Calls 2, 3, 4 are block sends
  for (size_t i = 1; i < 4; ++i) {
    JSON doc;
    ASSERT_TRUE(doc.fromString(bodies[i]).ok());
    EXPECT_EQ(std::string(doc.doc()["session_id"].GetString()), "test_session");
    EXPECT_EQ(doc.doc()["block_id"].GetUint(), 0U);
  }
}
} // namespace osquery
