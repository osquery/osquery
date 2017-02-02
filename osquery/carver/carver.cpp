/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/stat.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/carver.h>
#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {

const std::string kCarvePathPrefix = "osquery-carve-";

Carver::Carver(const std::set<std::string>& paths) {
  for (const auto& p : paths) {
    carvePaths_.insert(p);
  }
  carveDir_ = fs::temp_directory_path() / fs::path(kCarvePathPrefix +
              boost::uuids::to_string(boost::uuids::random_generator()()));
  auto ret = fs::create_directory(carveDir_);
  if (!ret) {
    LOG(ERROR) << "Unable to create carve file store";
  }
};

Carver::~Carver() {
  // TODO: Delete the temporary path
  // fs::remove_all(carveDir_);
}

void Carver::start() {
  // TODO: File Globbing. We should be able to carve entire paths.
  for (const auto& p : carvePaths_) {
    VLOG(1) << "[+] Carving " << p << " to " << this->carveDir_;
    Status s = carve(p);
    if (!s.ok()) {
      VLOG(1) << "Error carving " << p;
    }
  }
  
  // TODO:
  // s = compress();
  // s = encrypt();
  // s = exfill();
};

Status Carver::carve(const boost::filesystem::path& path) {
  // TODO: Check that the file is actually a file, as opposed to a soft link
  if (!fs::exists(path)) {
    return Status(1, "Path does not exist");
  }

  /// Our naive file carve.
  // TODO: Make this a more forensically robust carve
  std::ifstream src(path.string(), std::ios::binary);
  // TODO: Consider carving to a guid, and then mapping the guid in a ptree
  std::ofstream dst((carveDir_ / path.leaf()).string(), std::ios::binary);

  dst << src.rdbuf();

  src.close();
  dst.close();

  return Status(0, "Ok");
};

Status Carver::compress(const boost::filesystem::path& path) {
  return Status(0, "Ok");
};

Status Carver::encrypt(const boost::filesystem::path& path) {
  return Status(0, "Ok");
};
}
