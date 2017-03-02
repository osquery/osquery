/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/ptree.hpp>

#include <archive.h>
#include <archive_entry.h>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/carver/carver.h"
#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/utility.h"
#include "osquery/tables/system/hash.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

/// Prefix used for the temp FS where carved files are stored
const std::string kCarvePathPrefix = "osquery-carve-";

/// Prefix applied to the file carve tar archive.
const std::string kCarveNamePrefix = "carve-";

/// Database prefix used to directly access and manipulate our carver entries
const std::string kCarverDBPrefix = "carving.";

/*
 * Carver block chunking size. This specifies how big of a block size to
 * use when carving a file from disk.
 */
const size_t kBuffSize = 8192;

DECLARE_string(tls_hostname);

/// Session creation endpoint for forensic file carving
CLI_FLAG(string,
         carver_start_endpoint,
         "",
         "TLS/HTTPS init endpoint for forensic carver");

/// Data aggregation endpoint for forensic file carving
CLI_FLAG(
    string,
    carver_continue_endpoint,
    "",
    "TLS/HTTPS endpoint that receives carved content after session creation");

/// Size of blocks used for POSTing data back to remote endpoints
CLI_FLAG(int32,
         carver_block_size,
         8192,
         "Size of blocks used for POSTing data back to remote endpoints");

/// Helper function to update values related to a carve
void updateCarveValue(const std::string& guid,
                      const std::string& key,
                      const std::string& value) {
  std::string carve;
  auto s = getDatabaseValue(kQueries, kCarverDBPrefix + guid, carve);
  if (!s.ok()) {
    VLOG(1) << "Unable to update status of carve " << guid;
    return;
  }

  pt::ptree tree;
  try {
    std::stringstream ss(carve);
    pt::read_json(ss, tree);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Failed to parse carving entries: " << e.what();
    return;
  }

  tree.put(key, value);

  std::ostringstream os;
  pt::write_json(os, tree, false);
  setDatabaseValue(kQueries, kCarverDBPrefix + guid, os.str());
}

Carver::Carver(const std::set<std::string>& paths, const std::string& guid) {

  for (const auto& p : paths) {
    carvePaths_.insert(fs::path(p));
  }

  // Construct the uri we post our data back to:
  startUri_ = TLSRequestHelper::makeURI(FLAGS_carver_start_endpoint);
  contUri_ = TLSRequestHelper::makeURI(FLAGS_carver_continue_endpoint);

  // Generate a unique identifier for this carve
  carveGuid_ = guid;

  // TODO: Adding in a manifest file of all carved files might be nice.
  carveDir_ =
      fs::temp_directory_path() / fs::path(kCarvePathPrefix + carveGuid_);
  auto ret = fs::create_directory(carveDir_);
  if (!ret) {
    LOG(ERROR) << "Unable to create carve file store";
  }

  // Store the path to our archive for later exfiltration
  archivePath_ = carveDir_ / fs::path(kCarveNamePrefix + carveGuid_ + ".tgz");

  // Update the DB to reflect that the carve is pending.
  updateCarveValue(carveGuid_, "status", "PENDING");
};

Carver::~Carver() {
  /*
   * TODO: Currently when a carve finishes/fails, it's all deleted. Is this
   * our desired behavior? Would it be better to leave the carve tar somewhere
   * and just delete all temporary carved files?
   */
  fs::remove_all(carveDir_);
}

void Carver::start() {
  for (const auto& p : carvePaths_) {
    if (!fs::exists(p)) {
      LOG(WARNING) << "File does not exist on disk: " << p;
    } else {
      Status s = carve(p);
      if (!s.ok()) {
        LOG(WARNING) << "Failed to carve file: " << p;
      }
    }
  }

  std::set<fs::path> carvedFiles;
  for (const auto& p : platformGlob((carveDir_ / "*").string())) {
    carvedFiles.insert(fs::path(p));
  }

  auto s = compress(carvedFiles);
  if (!s.ok()) {
    LOG(WARNING) << "Failed to create carve archive: " << s.getMessage();
    updateCarveValue(carveGuid_, "status", "FAILED");
    return;
  }

  s = exfil(archivePath_);
  if (!s.ok()) {
    LOG(WARNING) << "Failed to post carve: " << s.getMessage();
    updateCarveValue(carveGuid_, "status", "FAILED");
    return;
  }
};

Status Carver::carve(const boost::filesystem::path& path) {
  PlatformFile src(path.string(), PF_OPEN_EXISTING);
  PlatformFile dst((carveDir_ / path.leaf()).string(), PF_CREATE_NEW);
  std::vector<char> inBuff(kBuffSize, 0);

  auto blkCount =
      ceil(static_cast<double>(src.size()) / static_cast<double>(kBuffSize));

  for (size_t i = 0; i < blkCount; i++) {
    src.read(inBuff.data(), kBuffSize);
    dst.write(inBuff.data(), kBuffSize);
  }

  return Status(0, "Ok");
};

Status Carver::compress(const std::set<boost::filesystem::path>& paths) {
  auto arch = archive_write_new();
  archive_write_set_format_zip(arch);
  archive_write_set_format_pax_restricted(arch);
  archive_write_open_filename(arch, archivePath_.string().c_str());

  for (const auto& f : paths) {
    PlatformFile pFile(f.string(), PF_OPEN_EXISTING);

    auto entry = archive_entry_new();
    archive_entry_set_pathname(entry, f.string().c_str());
    archive_entry_set_size(entry, pFile.size());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(arch, entry);

    // TODO: Chunking or a max file size.
    std::ifstream in(f.string(), std::ios::binary);
    std::stringstream buffer;
    buffer << in.rdbuf();
    archive_write_data(arch, buffer.str().c_str(), buffer.str().size());
    in.close();
    archive_entry_free(entry);
  }

  archive_write_close(arch);
  archive_write_free(arch);

  PlatformFile archFile(archivePath_.string(), PF_OPEN_EXISTING);
  updateCarveValue(carveGuid_, "size", std::to_string(archFile.size()));
  updateCarveValue(
      carveGuid_,
      "sha256",
      hashFromFile(HashType::HASH_TYPE_SHA256, archivePath_.string()));

  return Status(0, "Ok");
};

Status Carver::exfil(const boost::filesystem::path& path) {
  auto startRequest = Request<TLSTransport, JSONSerializer>(startUri_);

  // Perform the start request to get the session id
  PlatformFile pFile(path.string(), PF_OPEN_EXISTING);
  auto blkCount = ceil(static_cast<double>(pFile.size()) /
                       static_cast<double>(FLAGS_carver_block_size));
  pt::ptree startParams;

  startParams.put<int>("block_count", blkCount);
  startParams.put<int>("block_size", FLAGS_carver_block_size);
  startParams.put<int>("carve_size", pFile.size());
  startParams.put<std::string>("carve_id", carveGuid_);
  startParams.put<std::string>("node_key", getNodeKey("tls"));

  auto status = startRequest.call(startParams);

  // The call succeeded, store the session id used for future posts
  boost::property_tree::ptree startRecv;
  status = startRequest.getResponse(startRecv);
  if (!status.ok()) {
    return Status(status.getCode(), status.getMessage());
  }

  auto session_id = startRecv.get("session_id", "");
  if (session_id.empty()) {
    return Status(1, "No session_id received from remote endpoint");
  }

  VLOG(1) << "[+] Posting " << blkCount << " blocks of data";
  auto contRequest = Request<TLSTransport, JSONSerializer>(contUri_);
  for (int i = 0; i < blkCount; i++) {
    std::vector<char> block(FLAGS_carver_block_size, 0);
    pFile.read(block.data(), FLAGS_carver_block_size);

    pt::ptree params;
    params.put<int>("block_id", i);
    params.put<std::string>("session_id", session_id);
    params.put<std::string>("data", base64Encode(block.data()));

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
}
