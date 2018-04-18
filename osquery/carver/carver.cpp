/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifdef WIN32
#define _WIN32_DCOM

#include <Windows.h>
#endif

#include <boost/algorithm/string.hpp>

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

  JSON tree;
  s = tree.fromString(carve);
  if (!s.ok()) {
    VLOG(1) << "Failed to parse carve entries: " << s.what();
    return;
  }

  tree.add(key, value);

  std::string out;
  s = tree.toString(out);
  if (!s.ok()) {
    VLOG(1) << "Failed to serialize carve entries: " << s.what();
  }

  s = setDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, out);
  if (!s.ok()) {
    VLOG(1) << "Failed to update status of carve in database " << guid;
  }
}

Carver::Carver(const std::set<std::string>& paths,
               const std::string& guid,
               const std::string& requestId)
    : InternalRunnable("Carver") {
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
  setThreadName(name());
  // If status_ is not Ok, the creation of our tmp FS failed
  if (!status_.ok()) {
    LOG(WARNING) << "Carver has not been properly constructed";
    return;
  }
  for (const auto& p : carvePaths_) {
    // Ensure the file is a flat file on disk before carving
    PlatformFile pFile(p, PF_OPEN_EXISTING | PF_READ);
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

  PlatformFile uploadFile(uploadPath, PF_OPEN_EXISTING | PF_READ);
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
  PlatformFile src(path, PF_OPEN_EXISTING | PF_READ);
  PlatformFile dst(carveDir_ / path.leaf(), PF_CREATE_NEW | PF_WRITE);

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
  Request<TLSTransport, JSONSerializer> startRequest(startUri_);
  startRequest.setOption("hostname", FLAGS_tls_hostname);

  // Perform the start request to get the session id
  PlatformFile pFile(path, PF_OPEN_EXISTING | PF_READ);
  auto blkCount =
      static_cast<size_t>(ceil(static_cast<double>(pFile.size()) /
                               static_cast<double>(FLAGS_carver_block_size)));
  JSON startParams;

  startParams.add("block_count", blkCount);
  startParams.add("block_size", size_t(FLAGS_carver_block_size));
  startParams.add("carve_size", pFile.size());
  startParams.add("carve_id", carveGuid_);
  startParams.add("request_id", requestId_);
  startParams.add("node_key", getNodeKey("tls"));

  auto status = startRequest.call(startParams);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the session id for future posts
  JSON startRecv;
  status = startRequest.getResponse(startRecv);
  if (!status.ok()) {
    return status;
  }

  auto it = startRecv.doc().FindMember("session_id");
  if (it == startRecv.doc().MemberEnd()) {
    return Status(1, "No session_id received from remote endpoint");
  }
  if (!it->value.IsString()) {
    return Status(1, "Invalid session_id received from remote endpoint");
  }

  std::string session_id = it->value.GetString();
  if (session_id.empty()) {
    return Status(1, "Empty session_id received from remote endpoint");
  }

  Request<TLSTransport, JSONSerializer> contRequest(contUri_);
  contRequest.setOption("hostname", FLAGS_tls_hostname);
  for (size_t i = 0; i < blkCount; i++) {
    std::vector<char> block(FLAGS_carver_block_size, 0);
    auto r = pFile.read(block.data(), FLAGS_carver_block_size);

    if (r != FLAGS_carver_block_size && r > 0) {
      // resize the buffer to size we read as last block is likely smaller
      block.resize(r);
    }

    JSON params;
    params.add("block_id", i);
    params.add("session_id", session_id);
    params.add("request_id", requestId_);
    params.add("data", base64Encode(std::string(block.begin(), block.end())));

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
  Status s;
  auto guid = generateNewUUID();

  JSON tree;
  tree.add("carve_guid", guid);
  tree.add("time", getUnixTime());
  tree.add("status", "STARTING");
  tree.add("sha256", "");
  tree.add("size", -1);

  if (paths.size() > 1) {
    tree.add("path", boost::algorithm::join(paths, ","));
  } else {
    tree.add("path", *(paths.begin()));
  }

  std::string out;
  s = tree.toString(out);
  if (!s.ok()) {
    VLOG(1) << "Failed to serialize carve paths: " << s.what();
    return s;
  }

  s = setDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, out);
  if (!s.ok()) {
    return s;
  } else {
    auto requestId = Distributed::getCurrentRequestId();
    Dispatcher::addService(std::make_shared<Carver>(paths, guid, requestId));
  }
  return s;
}
} // namespace osquery
