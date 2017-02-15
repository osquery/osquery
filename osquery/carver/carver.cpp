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
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <archive.h>
#include <archive_entry.h>

#include <osquery/carver.h>
#include <osquery/dispatcher.h>
#include <osquery/enroll.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/utility.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

const std::string kCarvePathPrefix = "osquery-carve-";
const std::string kCarveNamePrefix = "carve-";
const std::string kEncryptionPassword = "malware";
const size_t kBuffSize = 8192;

const std::string kFirstSendBlockUri = "";
const std::string kSendBlockUri = "";

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

Carver::Carver(const std::set<std::string>& paths) {
  for (const auto& p : paths) {
    carvePaths_.insert(fs::path(p));
  }

  // Construct the uri we post our data back to:
  startUri_ = TLSRequestHelper::makeURI(FLAGS_carver_start_endpoint);
  contUri_ = TLSRequestHelper::makeURI(FLAGS_carver_continue_endpoint);

  // Generate a unique identifier for this carve
  carveGuid_ = boost::uuids::to_string(boost::uuids::random_generator()());

  // TODO: Adding in a manifest file of all carved files might be nice.
  carveDir_ =
      fs::temp_directory_path() / fs::path(kCarvePathPrefix + carveGuid_);
  auto ret = fs::create_directory(carveDir_);
  if (!ret) {
    LOG(ERROR) << "Unable to create carve file store";
  }
  archivePath_ = carveDir_ / fs::path(kCarveNamePrefix + carveGuid_ + ".tgz");
};

Carver::~Carver() {
  fs::remove_all(carveDir_);
}

void Carver::start() {
  for (const auto& p : carvePaths_) {
    if (!fs::exists(p)) {
      LOG(WARNING) << "File does not exist on disk: " << p;
    } else {
      Status s = carve(p);
      if (!s.ok()) {
        LOG(WARNING) << "Error carving file: " << p;
      }
    }
  }

  auto s = compress(carvePaths_);
  if (!s.ok()) {
    LOG(WARNING) << "Error compressing file carve archives: " << s.getMessage();
    // TODO: Cleanup?
    return;
  }

  s = exfil(archivePath_);
  if (!s.ok()) {
    LOG(WARNING) << "Error compressing file carve archives: " << s.getMessage();
    // TODO: Cleanup?
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
  archive_write_set_passphrase(arch, kEncryptionPassword.c_str());
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

  VLOG(1) << "[+] Archive written to " << archivePath_.string();
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
    VLOG(1) << "Did not receive session id";
    return Status(1, "Did not receive a session id from endpoint");
  }

  auto session_id = startRecv.get("session_id", "");
  if (session_id.empty()) {
    // TODO: Remove VLOG statement here.
    VLOG(1) << "Did not receive session id from remote endpoint";
    return Status(1, "No session_id received from remote endpoint");
  }
  VLOG(1) << "[+] Got session ID: " << session_id;
  VLOG(1) << "[+] Posting " << blkCount << " blocks of data";
  auto contRequest = Request<TLSTransport, JSONSerializer>(contUri_);
  for (int i = 0; i < blkCount; i++) {
    std::vector<char> block(FLAGS_carver_block_size, 0);
    pFile.read(block.data(), FLAGS_carver_block_size);

    pt::ptree params;
    params.put<int>("block_id", i);
    params.put<std::string>("session_id", session_id);
    params.put<std::string>("data", base64Encode(block.data()));

    // TODO: Fill in the status of the carve as "Failed/Retrying" or something.
    // along with pause/sleep logic
    // TODO: Is this needed? I don't see why it would be...
    // contRequest.setOption("hostname", FLAGS_tls_hostname);
    status = contRequest.call(params);
    if (!status.ok()) {
      VLOG(1) << "Post of carved block " << i
              << " failed: " << status.getMessage();
      continue;
    }

    // TODO: Do we need a response?
    // Check the response to ensure the endpoint received our carved block
    boost::property_tree::ptree contRecv;
    status = contRequest.getResponse(contRecv);
    if (!status.ok()) {
      VLOG(1) << "[-] Error posting block " << i;
    }

    // TODO: Check the response code
    //    - If it failed, do we try again? Should there be a flag?
    //    - If retry, should we keep track of failed attempts?
    //    - Should we note how many blocks have been sent in the DB?
  }

  // TODO: Update the DB entry with a fail or success
  
  return Status(0, "Ok");
};
}
