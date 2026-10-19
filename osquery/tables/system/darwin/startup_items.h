/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#pragma once

#include <string>
#include <vector>

namespace osquery {
namespace tables {

struct BtmUserStoreFile {
  std::string filename;
  std::string user_identifier;
};

/// The archives that make up one version of the BTM database.
struct BtmDatabaseFiles {
  /// e.g. BackgroundItems-v16.btm
  std::string global_filename;

  /// e.g. BackgroundItems-v18-<user UUID>.btm, only present since version 18
  std::vector<BtmUserStoreFile> user_store_files;
};

/**
 * @brief Pick the archives of the newest BTM database version
 *
 * Older versions are left on disk after macOS upgrades, so the newest version
 * is chosen by the number in the filename rather than by modification time.
 *
 * @param filenames The filenames found in the BTM directory
 */
BtmDatabaseFiles selectBtmDatabaseFiles(
    const std::vector<std::string>& filenames);

} // namespace tables
} // namespace osquery
