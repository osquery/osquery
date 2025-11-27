/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
};

// Parse disposition bitmask to determine status
// DispositionValues: 0x01 = Enabled, 0x02 = Allowed, 0x04 = Hidden, 0x08 =
// Notified
std::string getStatusFromDisposition(const pt::ptree& item) {
  if (item.count("disposition") == 0) {
    return "enabled"; // Default if disposition is missing
  }

  // Try to get disposition as integer first
  int disposition = -1;
  try {
    disposition = item.get<int>("disposition", -1);
  } catch (...) {
    // If not an integer, try as string
    std::string disposition_str = item.get<std::string>("disposition", "");
    auto result = tryTo<int>(disposition_str, 10);
    if (!result.isError()) {
      disposition = result.get();
    }
  }

  if (disposition < 0) {
    return "enabled"; // Default if parsing fails
  }

  // Check if Enabled bit (0x01) is set
  if (disposition & 0x01) {
    return "enabled";
  } else {
    return "disabled";
  }
}

void genLibraryStartupItems(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      if (!fs::exists(it->status()) || !fs::is_directory(it->status())) {
        continue;
      }

      Row r;
      r["name"] = it->path().string();
      r["path"] = it->path().string();
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      r["source"] = sysdir;
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

void genBtmStartupItems(QueryData& results) {
  const std::string kBtmDirectory =
      "/private/var/db/com.apple.backgroundtaskmanagement/";

  // Find the most recently modified .btm file using SQL query
  std::string query = "SELECT path FROM file WHERE directory = '" +
                      kBtmDirectory +
                      "' AND filename LIKE '%.btm' ORDER BY mtime DESC LIMIT 1";
  SQL sql(query);
  if (!sql.ok() || sql.rows().empty()) {
    return;
  }

  std::string most_recent_btm_file = sql.rows()[0].at("path");

  // Parse the plist file
  pt::ptree tree;
  auto parse_status = osquery::parsePlist(most_recent_btm_file, tree);
  if (!parse_status.ok()) {
    return;
  }

  // Extract startup items from the plist
  // The structure may vary, but typically contains entries with paths
  // Common structures: root-level array or dictionary with entries
  try {
    // Check if this is a binary plist (NSKeyedArchiver format)
    // Look for $top.store which contains the actual data
    if (tree.count("$top") > 0 && tree.get_child("$top").count("store") > 0) {
      auto store = tree.get_child("$top.store");

      // Log all keys and values for store entries
      VLOG(1) << "genBtmStartupItems: $top.store has " << store.size()
              << " entries";
      for (const auto& store_entry : store) {
        VLOG(1) << "genBtmStartupItems: store entry key: " << store_entry.first;
        if (!store_entry.second.empty()) {
          VLOG(1) << "genBtmStartupItems: store entry has "
                  << store_entry.second.size() << " children";
          for (const auto& child : store_entry.second) {
            VLOG(1) << "genBtmStartupItems:   - " << child.first << " = "
                    << child.second.data();
          }
        } else {
          VLOG(1) << "genBtmStartupItems: store entry value: "
                  << store_entry.second.data();
        }
      }

      // The store might contain references or direct data
      // Also check $objects for actual paths
      if (tree.count("$objects") > 0) {
        auto objects = tree.get_child("$objects");

        // Extract paths from $objects that look like executables or plist files
        for (const auto& obj : objects) {
          // Log all keys and values for this object entry
          VLOG(1) << "genBtmStartupItems: $objects entry key: " << obj.first;
          if (!obj.second.empty()) {
            VLOG(1) << "genBtmStartupItems: $objects entry has "
                    << obj.second.size() << " children";
            for (const auto& child : obj.second) {
              VLOG(1) << "genBtmStartupItems:   - " << child.first << " = "
                      << child.second.data();
            }
          } else {
            VLOG(1) << "genBtmStartupItems: $objects entry value: "
                    << obj.second.data();
          }

          std::string value = obj.second.data();

          // Look for absolute paths or file:// URLs
          if (!value.empty() &&
              (value[0] == '/' || value.find("file://") == 0)) {
            // Filter for executables, plist files, or app bundles
            bool is_valid = false;
            std::string path = value;

            // Handle file:// URLs
            if (value.find("file://") == 0) {
              path = value.substr(7); // Remove "file://"
              // URL decode if needed (simple case - just remove %20 -> space)
              size_t pos = 0;
              while ((pos = path.find("%20", pos)) != std::string::npos) {
                path.replace(pos, 3, " ");
                pos += 1;
              }
            }

            // Check if it's a plist file, executable, or app bundle
            if (path.find(".plist") != std::string::npos ||
                path.find(".app/") != std::string::npos ||
                path.find("/Contents/MacOS/") != std::string::npos ||
                (path[0] == '/' && fs::path(path).extension().empty() &&
                 path.find("/bin/") != std::string::npos)) {
              is_valid = true;
            }

            if (is_valid) {
              Row r;
              r["type"] = "Startup Item";
              r["source"] = kBtmDirectory;
              // Try to find corresponding store entry with disposition
              std::string status = "enabled";
              for (const auto& store_entry : store) {
                // Check if this store entry has disposition information
                if (store_entry.second.count("disposition") > 0) {
                  // Use getStatusFromDisposition to extract status
                  status = getStatusFromDisposition(store_entry.second);
                  break;
                }
              }
              r["status"] = status;
              r["path"] = path;
              r["name"] = fs::path(path).filename().string();
              results.push_back(r);
            }
          }
        }
      }
    }
  } catch (const std::exception& e) {
    // Silently handle exceptions
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // Find system wide startup items in Library directories.
  for (const auto& dir : kLibraryStartupItemPaths) {
    genLibraryStartupItems(dir, results);
  }

  // Find startup items from Background Task Management (.btm files)
  genBtmStartupItems(results);

  return results;
}
} // namespace tables
} // namespace osquery
