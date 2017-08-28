/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifdef WIN32
#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/carver/carver.h"
#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"
#include "osquery/tables/system/hash.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

DECLARE_string(tls_hostname);

/// Session creation endpoint for forensic file carve
CLI_FLAG(string,
         carver_start_endpoint,
         "",
         "TLS/HTTPS init endpoint for forensic carver");

/// Data aggregation endpoint for forensic file carve
CLI_FLAG(
    string,
    carver_continue_endpoint,
    "",
    "TLS/HTTPS endpoint that receives carved content after session creation");

/// Size of blocks used for POSTing data back to remote endpoints
CLI_FLAG(uint32,
         carver_block_size,
         8192,
         "Size of blocks used for POSTing data back to remote endpoints");

CLI_FLAG(bool,
         disable_carver,
         true,
         "Disable the osquery file carver (default true)");

CLI_FLAG(bool,
         carver_disable_function,
         FLAGS_disable_carver,
         "Disable the osquery file carver function (default true)");

CLI_FLAG(bool,
         carver_compression,
         false,
         "Compress archives using zstd prior to upload (default false)");

DECLARE_uint64(read_max);

/// Helper function to update values related to a carve
void updateCarveValue(const std::string& guid,
                      const std::string& key,
                      const std::string& value) {
  std::string carve;
  auto s = getDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, carve);
  if (!s.ok()) {
    VLOG(1) << "Failed to update status of carve in database " << guid;
    return;
  }

  pt::ptree tree;
  try {
    std::stringstream ss(carve);
    pt::read_json(ss, tree);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Failed to parse carve entries: " << e.what();
    return;
  }

  tree.put(key, value);

  std::ostringstream os;
  pt::write_json(os, tree, false);
  s = setDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, os.str());
  if (!s.ok()) {
    VLOG(1) << "Failed to update status of carve in database " << guid;
  }
}

Carver::Carver(const std::set<std::string>& paths,
               const std::string& guid,
               const std::string& requestId) {
  status_ = Status(0, "Ok");
  for (const auto& p : paths) {
    carvePaths_.insert(fs::path(p));
  }

  // Construct the uri we post our data back to:
  startUri_ = TLSRequestHelper::makeURI(FLAGS_carver_start_endpoint);
  contUri_ = TLSRequestHelper::makeURI(FLAGS_carver_continue_endpoint);

  // Generate a unique identifier for this carve
  carveGuid_ = guid;

  // Stash the work ID to be POSTed with the carve initial request
  requestId_ = requestId;

  // TODO: Adding in a manifest file of all carved files might be nice.
  carveDir_ =
      fs::temp_directory_path() / fs::path(kCarvePathPrefix + carveGuid_);
  auto ret = fs::create_directory(carveDir_);
  if (!ret) {
    status_ = Status(1, "Failed to create carve file store");
    return;
  }

  // Store the path to our archive for later exfiltration
  archivePath_ = carveDir_ / fs::path(kCarveNamePrefix + carveGuid_ + ".tar");
  compressPath_ =
      carveDir_ / fs::path(kCarveNamePrefix + carveGuid_ + ".tar.zst");

  // Update the DB to reflect that the carve is pending.
  updateCarveValue(carveGuid_, "status", "PENDING");
};

Carver::~Carver() {
  fs::remove_all(carveDir_);
}

void Carver::start() {
  // If status_ is not Ok, the creation of our tmp FS failed
  if (!status_.ok()) {
    LOG(WARNING) << "Carver has not been properly constructed";
    return;
  }
  for (const auto& p : carvePaths_) {
    // Ensure the file is a flat file on disk before carving
    PlatformFile pFile(p.string(), PF_OPEN_EXISTING | PF_READ);
    if (!pFile.isValid() || isDirectory(p)) {
      VLOG(1) << "File does not exist on disk or is subdirectory: " << p;
      continue;
    }
    Status s = carve(p);
    if (!s.ok()) {
      VLOG(1) << "Failed to carve file " << p << " " << s.getMessage();
    }
  }

  std::set<fs::path> carvedFiles;
  for (const auto& p : platformGlob((carveDir_ / "*").string())) {
    carvedFiles.insert(fs::path(p));
  }

  auto s = archive(carvedFiles, archivePath_);
  if (!s.ok()) {
    VLOG(1) << "Failed to create carve archive: " << s.getMessage();
    updateCarveValue(carveGuid_, "status", "ARCHIVE FAILED");
    return;
  }

  fs::path uploadPath;
  if (FLAGS_carver_compression) {
    uploadPath = compressPath_;
    s = compress(archivePath_, compressPath_);
    if (!s.ok()) {
      VLOG(1) << "Failed to compress carve archive: " << s.getMessage();
      updateCarveValue(carveGuid_, "status", "COMPRESS FAILED");
      return;
    }
  } else {
    uploadPath = archivePath_;
  }

  PlatformFile uploadFile(uploadPath.string(), PF_OPEN_EXISTING | PF_READ);
  updateCarveValue(carveGuid_, "size", std::to_string(uploadFile.size()));

  std::string uploadHash =
      (uploadFile.size() > FLAGS_read_max)
          ? "-1"
          : hashFromFile(HashType::HASH_TYPE_SHA256, uploadPath.string());
  if (uploadHash == "-1") {
    VLOG(1)
        << "Archive file size exceeds read max, skipping integrity computation";
  }
  updateCarveValue(carveGuid_, "sha256", uploadHash);

  s = postCarve(uploadPath);
  if (!s.ok()) {
    VLOG(1) << "Failed to post carve: " << s.getMessage();
    updateCarveValue(carveGuid_, "status", "DATA POST FAILED");
    return;
  }
};

Status Carver::carve(const boost::filesystem::path& path) {
  PlatformFile src(path.string(), PF_OPEN_EXISTING | PF_READ);
  PlatformFile dst((carveDir_ / path.leaf()).string(),
                   PF_CREATE_NEW | PF_WRITE);

  if (!dst.isValid()) {
    return Status(1, "Destination tmp FS is not valid.");
  }

  auto blkCount = ceil(static_cast<double>(src.size()) /
                       static_cast<double>(FLAGS_carver_block_size));

  std::vector<char> inBuff(FLAGS_carver_block_size, 0);
  for (size_t i = 0; i < blkCount; i++) {
    inBuff.clear();
    auto bytesRead = src.read(inBuff.data(), FLAGS_carver_block_size);
    if (bytesRead > 0) {
      auto bytesWritten = dst.write(inBuff.data(), bytesRead);
      if (bytesWritten < 0) {
        return Status(1, "Error writing bytes to tmp fs");
      }
    }
  }

  return Status(0, "Ok");
};

Status Carver::postCarve(const boost::filesystem::path& path) {
  auto startRequest = Request<TLSTransport, JSONSerializer>(startUri_);

  // Perform the start request to get the session id
  PlatformFile pFile(path.string(), PF_OPEN_EXISTING | PF_READ);
  auto blkCount =
      static_cast<size_t>(ceil(static_cast<double>(pFile.size()) /
                               static_cast<double>(FLAGS_carver_block_size)));
  pt::ptree startParams;

  startParams.put<size_t>("block_count", blkCount);
  startParams.put<size_t>("block_size", FLAGS_carver_block_size);
  startParams.put<size_t>("carve_size", pFile.size());
  startParams.put<std::string>("carve_id", carveGuid_);
  startParams.put<std::string>("request_id", requestId_);
  startParams.put<std::string>("node_key", getNodeKey("tls"));

  auto status = startRequest.call(startParams);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the session id for future posts
  boost::property_tree::ptree startRecv;
  status = startRequest.getResponse(startRecv);
  if (!status.ok()) {
    return status;
  }

  auto session_id = startRecv.get("session_id", "");
  if (session_id.empty()) {
    return Status(1, "No session_id received from remote endpoint");
  }

  auto contRequest = Request<TLSTransport, JSONSerializer>(contUri_);
  for (size_t i = 0; i < blkCount; i++) {
    std::vector<char> block(FLAGS_carver_block_size, 0);
    auto r = pFile.read(block.data(), FLAGS_carver_block_size);

    if (r != FLAGS_carver_block_size && r > 0) {
      // resize the buffer to size we read as last block is likely smaller
      block.resize(r);
    }

    pt::ptree params;
    params.put<size_t>("block_id", i);
    params.put<std::string>("session_id", session_id);
    params.put<std::string>("request_id", requestId_);
    params.put<std::string>(
        "data", base64Encode(std::string(block.begin(), block.end())));

    // TODO: Error sending files.
    status = contRequest.call(params);
    if (!status.ok()) {
      VLOG(1) << "Post of carved block " << i
              << " failed: " << status.getMessage();
      continue;
    }
  }

  updateCarveValue(carveGuid_, "status", "SUCCESS");
  return Status(0, "Ok");
};

Status carvePaths(const std::set<std::string>& paths) {
  auto guid = generateNewUUID();

  pt::ptree tree;
  tree.put("carve_guid", guid);
  tree.put("time", getUnixTime());
  tree.put("status", "STARTING");
  tree.put("sha256", "");
  tree.put("size", -1);

  if (paths.size() > 1) {
    tree.put("path", boost::algorithm::join(paths, ","));
  } else {
    tree.put("path", *(paths.begin()));
  }

  std::ostringstream os;
  pt::write_json(os, tree, false);
  auto s = setDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, os.str());
  if (!s.ok()) {
    return s;
  } else {
    auto requestId = Distributed::getCurrentRequestId();
    Dispatcher::addService(std::make_shared<Carver>(paths, guid, requestId));
  }
  return s;
}
} // namespace osquery
