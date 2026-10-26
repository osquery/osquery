/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace osquery {
namespace tables {
namespace jetbrains_plugins_internal {

inline constexpr std::size_t kMaxDecompressedPluginXmlSize = 1024U * 1024U;

enum class ExtractionStatus {
  Success,
  TargetNotFound,
  ArchiveError,
  DeclaredSizeLimitExceeded,
  ExpandedSizeLimitExceeded,
};

struct ExtractionResult final {
  ExtractionStatus status{ExtractionStatus::TargetNotFound};
  std::string path;
  std::vector<char> content;
};

ExtractionResult extractSpecificFileFromArchive(
    const std::string& archive_file_path,
    const std::string& target_file_path,
    std::size_t maximum_decompressed_size);

} // namespace jetbrains_plugins_internal
} // namespace tables
} // namespace osquery
