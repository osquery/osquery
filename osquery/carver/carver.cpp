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

//#include <boost/iostreams/filtering_streambuf.hpp>
//#include <boost/iostreams/copy.hpp>
//#include <boost/iostreams/filter/gzip.hpp>

#include <archive.h>
#include <archive_entry.h>

#include <osquery/carver.h>
#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {

const std::string kCarvePathPrefix = "osquery-carve-";
const std::string kCarveNamePrefix = "carve-";
const std::string kEncryptionPassword = "malware";
const size_t kBuffSize = 8192;

Carver::Carver(const std::set<std::string>& paths) {
  for (const auto& p : paths) {
    carvePaths_.insert(fs::path(p));
  }
  carveGuid_ = boost::uuids::to_string(boost::uuids::random_generator()());
  carveDir_ =
      fs::temp_directory_path() / fs::path(kCarvePathPrefix + carveGuid_);
  auto ret = fs::create_directory(carveDir_);
  if (!ret) {
    LOG(ERROR) << "Unable to create carve file store";
  }
  archivePath_ = carveDir_ / fs::path(kCarveNamePrefix + carveGuid_ + ".tgz");
};

Carver::~Carver() {
  // TODO: Delete the temporary path
  // fs::remove_all(carveDir_);
}

void Carver::start() {
  // TODO: File Globbing. We should be able to carve entire paths.
  for (const auto& p : carvePaths_) {
    if(!fs::exists(p)){
      LOG(WARNING) << "File does not exist on disk: " << p;
    } else {
      Status s = carve(p);
      if (!s.ok()) {
        LOG(WARNING) << "Error carving file: " << p;
      }
    }
  }

  // TODO: Do you need to pass this? Can `compress` just read the var?
  auto s = compress(carvePaths_);
  if(!s.ok()){
    LOG(WARNING) << "Error compressing file carve archives: " << s.getMessage();
    // TODO: Cleanup?
    return;
  }

  s = exfill(archivePath_);
  if(!s.ok()){
    LOG(WARNING) << "Error compressing file carve archives: " << s.getMessage();
    // TODO: Cleanup?
    return;
  }
};

Status Carver::carve(const boost::filesystem::path& path) {
  // TODO: Use platform file to check if file is actual file or not.
  // TODO: Check that the file is actually a file, as opposed to a soft link

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

// TODO: All of the archive functions have a return value indicating success
// let's consider checking those values and failing out, and what fails Look
// like..
Status Carver::compress(const std::set<boost::filesystem::path>& paths) {

  auto arch = archive_write_new();
  //archive_write_add_filter_gzip(arch);
  archive_write_set_format_zip(arch);
  //archive_write_set_filter_option(arch, "gzip", "compression-level", "5");
  archive_write_set_format_pax_restricted(arch);
  archive_write_set_passphrase(arch, kEncryptionPassword.c_str());
  archive_write_open_filename(arch, archivePath_.string().c_str());
  for(const auto& f : paths){
    // TODO: Probably can't do this in Windows :(
    struct stat st;
    stat(f.string().c_str(), &st);
    auto entry = archive_entry_new();
    archive_entry_set_pathname(entry, f.string().c_str());
    archive_entry_set_size(entry, st.st_size);

    archive_entry_set_filetype(entry, AE_IFREG);

    archive_entry_set_perm(entry, 0644);
    archive_write_header(arch, entry);

    // TODO: Chunking? Either that or file limits? Like 500 MB or something?
    std::vector<char> buff(kBuffSize);
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

Status Carver::exfil(const boost::filesystem::path& path){



  return Status(0, "Ok");
};

}
