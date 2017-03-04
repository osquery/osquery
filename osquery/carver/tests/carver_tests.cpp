/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <gtest/gtest.h>

#include <osquery/core.h>

#include "osquery/carver/carver.h"
#include "osquery/core/json.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tests/test_util.h"

namespace osquery {

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

/// Prefix used for temporary carve FS store.
const std::string kTestCarvePathPrefix = "test-osquery-carve-";

/// Prefix used for posix tar archive.
const std::string kTestCarveNamePrefix = "test-carve-";

/// Database prefix used to directly access and manipulate our carver entries
const std::string kCarverDBPrefix = "carving.";

std::string genGuid() {
  return boost::uuids::to_string(boost::uuids::random_generator()());
};

class CarverTests : public testing::Test {
 public:
  CarverTests() {
    fs::create_directories(kFakeDirectory + "/files_to_carve/");
    writeTextFile(kFakeDirectory + "/secrets.txt",
                  "This is a message I'd rather no one saw.");
    writeTextFile(kFakeDirectory + "/evil.exe",
                  "MZP\x00\x02\x00\x00\x00\x04\x00\x0f\x00\xff\xff");

    auto paths = platformGlob(kFakeDirectory + "/files_to_carve/*");
    for (const auto& p : paths) {
      carvePaths.insert(p);
    }
  };

  std::set<std::string>& getCarvePaths() {
    return carvePaths;
  }

 protected:
  void SetUp() override {
    createMockFileStructure();
  }

  void TearDown() override {
    tearDownMockFileStructure();
  }

 private:
  std::set<std::string> carvePaths;
};

TEST_F(CarverTests, test_carve_files_locally) {
  auto guid_ = genGuid();
  auto paths_ = getCarvePaths();
  Carver carve(getCarvePaths(), guid_);

  /*
  // TODO: As the carve DB entry happens in the table, this entry wont exist.
  std::string carveId;
  std::cout << "[+] Scanning database for " << kCarverDBPrefix + guid_ <<
  std::endl; auto s = getDatabaseValue(kQueries, kCarverDBPrefix + guid_,
  carveId); EXPECT_TRUE(s.ok());

  pt::ptree tree;
  std::stringstream ss(carveId);
  EXPECT_NO_THROW(pt::read_json(ss, tree));

  std::string status = tree.get<std::string>("status");
  EXPECT_EQ(status, "PENDING");
  */
  Status s;
  for (const auto& p : paths_) {
    s = carve.carve(fs::path(p));
    EXPECT_TRUE(s.ok());
  }

  auto paths = platformGlob(kTestCarvePathPrefix + "/*");
  std::set<fs::path> carves;
  for (const auto& p : paths) {
    carves.insert(fs::path(p));
  }

  EXPECT_EQ(carves.size(), static_cast<const unsigned int>(2));
  s = carve.compress(carves);
  EXPECT_TRUE(s.ok());

  auto tarPath = kTestCarveNamePrefix + guid_ + ".tgz";
  PlatformFile tar(tarPath, PF_OPEN_EXISTING);
  EXPECT_TRUE(tar.isValid());
  EXPECT_GT(tar.size(), static_cast<const unsigned int>(0));
}
}
