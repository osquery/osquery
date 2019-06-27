/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
#include <osquery/utils/json/json.h>

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
  std::set<std::string>& getCarvePaths() {
    return carvePaths;
  }

  fs::path const& getWorkingDir() const {
    return working_dir_;
  }

 protected:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();

    // Force registry to use ephemeral database plugin
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();

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

    auto paths = platformGlob((files_to_carve_dir_ / "*").string());
    for (const auto& p : paths) {
      carvePaths.insert(p);
    }
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
