/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <magic.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/posix/magic.h>

namespace osquery {

// First the database compiled at build time from the vendored libmagic rules
// and installed with osquery (see cmake/install_directives.cmake), then the
// paths where systems keep theirs. A compiled database is locked to the format
// version of the libmagic that produced it, and systems usually ship one from
// a different libmagic than the vendored one, so the table skips the entries
// that the vendored libmagic cannot load.
#ifdef __APPLE__
FLAG(string,
     magic_db_files,
     "/private/var/osquery/magic.mgc:/usr/share/file/magic.mgc:"
     "/usr/share/misc/magic.mgc",
     "Colon(:) separated list of magic databases for the magic table, used "
     "when a query does not constrain magic_db_files");
#else
FLAG(string,
     magic_db_files,
     "/opt/osquery/share/osquery/magic.mgc:/usr/share/file/magic.mgc:"
     "/usr/share/misc/magic.mgc",
     "Colon(:) separated list of magic databases for the magic table, used "
     "when a query does not constrain magic_db_files");
#endif

namespace tables {

namespace {

#ifndef OSQUERY_LIBMAGIC_DB_VERSION
#error "OSQUERY_LIBMAGIC_DB_VERSION comes from the thirdparty_libmagic target"
#endif

// The compiled database format version the vendored libmagic loads.
constexpr std::uint32_t kLibmagicDbVersion = OSQUERY_LIBMAGIC_DB_VERSION;

// The first word of a compiled database (MAGICNO in libmagic's src/file.h).
constexpr std::uint32_t kCompiledMagicDbMagicNumber = 0xF11E041C;

constexpr char const* kMagicFileDBSep = ":";

std::uint32_t swapBytes(std::uint32_t value) {
  return ((value & 0x000000FFU) << 24) | ((value & 0x0000FF00U) << 8) |
         ((value & 0x00FF0000U) >> 8) | ((value & 0xFF000000U) >> 24);
}

// The format version of the compiled database at path, read the way
// libmagic's apprentice_map() reads it, or nothing if path is not one.
std::optional<std::uint32_t> getCompiledMagicDbVersion(
    const std::string& path) {
  boost::system::error_code ec;
  if (!boost::filesystem::is_regular_file(path, ec)) {
    return std::nullopt;
  }

  std::ifstream stream(path, std::ios::binary);
  std::array<std::uint32_t, 2> header{};
  if (!stream.read(reinterpret_cast<char*>(header.data()), sizeof(header))) {
    return std::nullopt;
  }

  if (header[0] == kCompiledMagicDbMagicNumber) {
    return header[1];
  }

  // Compiled on a host of the other byte order
  if (swapBytes(header[0]) == kCompiledMagicDbMagicNumber) {
    return swapBytes(header[1]);
  }

  return std::nullopt;
}

} // namespace

bool isLoadableMagicDatabase(const std::string& path,
                             std::uint32_t supported_version) {
  // libmagic's mkdbname(): the compiled database is path, ending in .mgc
  const std::string kCompiledExtension = ".mgc";
  auto compiled_path = boost::algorithm::ends_with(path, kCompiledExtension)
                           ? path
                           : path + kCompiledExtension;

  if (getCompiledMagicDbVersion(compiled_path) == supported_version) {
    return true;
  }

  // Otherwise libmagic parses path itself as rule source. That only works if
  // it is rule source, and not a compiled database of any version.
  boost::system::error_code ec;
  return boost::filesystem::exists(path, ec) &&
         !getCompiledMagicDbVersion(path).has_value();
}

QueryData genMagicData(QueryContext& context) {
  QueryData results;

  // No default flags
  magic_t magic_cookie = magic_open(MAGIC_NONE);
  if (magic_cookie == nullptr) {
    VLOG(1) << "Unable to initialize magic library";
    return results;
  }

  std::string magic_db_files;
  if (context.hasConstraint("magic_db_files")) {
    // A list given in the query is loaded as given.
    auto magic_files = context.constraints["magic_db_files"].getAll(EQUALS);
    magic_db_files = boost::algorithm::join(magic_files, kMagicFileDBSep);

  } else {
    std::vector<std::string> flag_entries;
    boost::algorithm::split(flag_entries,
                            FLAGS_magic_db_files,
                            boost::algorithm::is_any_of(kMagicFileDBSep));

    std::vector<std::string> magic_files;
    for (const auto& entry : flag_entries) {
      if (entry.empty()) {
        continue;
      }

      if (isLoadableMagicDatabase(entry, kLibmagicDbVersion)) {
        magic_files.push_back(entry);
      } else {
        VLOG(1) << "Skipping magic database " << entry
                << ": it does not exist, or is not compiled for format version "
                << kLibmagicDbVersion;
      }
    }

    if (magic_files.empty()) {
      LOG(WARNING) << "No loadable magic database in --magic_db_files="
                   << FLAGS_magic_db_files
                   << " (compiled databases must be format version "
                   << kLibmagicDbVersion << ")";
      magic_close(magic_cookie);
      return results;
    }

    magic_db_files = boost::algorithm::join(magic_files, kMagicFileDBSep);
  }

  if (magic_load(magic_cookie, magic_db_files.c_str()) != 0) {
    LOG(WARNING) << "Unable to load magic list of database: " << magic_db_files
                 << " because: " << magic_error(magic_cookie);
    magic_close(magic_cookie);
    return results;
  }

  // Iterate through all the provided paths
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    Row r;
    r["path"] = path_string;
    r["magic_db_files"] = magic_db_files;

    auto data = magic_file(magic_cookie, path_string.c_str());
    if (data != nullptr) {
      r["data"] = data;
    }

    // Retrieve MIME type
    magic_setflags(magic_cookie, MAGIC_MIME_TYPE);
    auto mime_type = magic_file(magic_cookie, path_string.c_str());
    if (mime_type != nullptr) {
      r["mime_type"] = mime_type;
    }

    // Retrieve MIME encoding
    magic_setflags(magic_cookie, MAGIC_MIME_ENCODING);
    auto mime_encoding = magic_file(magic_cookie, path_string.c_str());
    if (mime_encoding != nullptr) {
      r["mime_encoding"] = mime_encoding;
    }

    results.push_back(r);
  }

  magic_close(magic_cookie);
  return results;
}
} // namespace tables
} // namespace osquery
