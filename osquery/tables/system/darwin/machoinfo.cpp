/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <LIEF/LIEF.hpp>
#include <sstream>

#include <iostream>

namespace osquery {
namespace tables {

QueryData genMachoInfo(QueryContext& context) {
  QueryData results;
  std::cout << "Hi!!" << std::endl;
  /*
  auto paths = context.constraints["path"].getAll(EQUALS);

  // Expand contstraints
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  auto config = LIEF::MachO::ParserConfig().deep();
  boost::system::error_code ec;

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-macho files
      if (!LIEF::MachO::is_macho(path_string)) {
        continue;
      }

      std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
          LIEF::MachO::Parser::parse(path_string, config.deep());

      for (const auto& data : mac_binary->begin()) {
        Row r;
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
        if (data.has_encryption_info()) {
          r["is_encrypted"] = INTEGER(1);
        } else {
          r["is_encrypted"] = INTEGER(0);
        }
        if (data.has_entrypoint()) {
          std::ostringstream stream;
          stream << std::hex << data.entrypoint();
          r["entrypoint"] = stream.str();
        }

        if (data.has_build_version()) {
          std::ostringstream ss;

          for (const auto& min : data.build_version().minos()) {
            ss << std::to_string(min) << ".";
          }
          r["build_version_min"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");
          for (const auto& build : data.build_version().sdk()) {
            ss << std::to_string(build) << ".";
          }
          r["build_version_sdk"] = ss.str().substr(0, ss.str().size() - 1);
        }
        if (data.has_version_min()) {
          std::ostringstream ss;

          for (const auto& min : data.version_min().version()) {
            ss << std::to_string(min) << ".";
          }
          r["version_min"] = ss.str().substr(0, ss.str().size() - 1);
          ss.str("");
          for (const auto& build : data.version_min().sdk()) {
            ss << std::to_string(build) << ".";
          }
          r["version_sdk"] = ss.str().substr(0, ss.str().size() - 1);
        }

        r["is_pie"] = INTEGER(data.is_pie());
        r["has_nx"] = INTEGER(data.has_nx());
        results.push_back(r);
      }
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse Mach-O file: " << error.what();
    }
  }
  */
  return results;
}
} // namespace tables
} // namespace osquery
