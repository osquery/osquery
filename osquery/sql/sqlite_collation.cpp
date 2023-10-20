/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>

#include <osquery/core/flags.h>

#include <sqlite3.h>

namespace osquery {
/**
 * @brief Split version string into numeric and alphabetic character segments.
 */
static std::vector<std::vector<std::string>> versionSplit(
    const std::string& version) {
  std::vector<std::vector<std::string>> result;
  std::regex ver_pattern("(\\d+|[a-zA-Z]+)");
  std::sregex_token_iterator iter_end;
  std::istringstream iss(version);
  std::string segment;

  // Split version into segments on periods.
  while (getline(iss, segment, '.')) {
    std::vector<std::string> seg_pieces;
    std::sregex_token_iterator iter_begin(
        segment.begin(), segment.end(), ver_pattern);

    // Split segment into pieces of consecutive alphabetic and numeric
    // characters.
    while (iter_begin != iter_end) {
      seg_pieces.push_back(*iter_begin++);
    }

    result.push_back(seg_pieces);
  }

  return result;
}

/**
 * @brief Collate version strings. (Only compares alphanumeric characters.)
 */
static int versionCollate(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  const std::string lver(static_cast<const char*>(pKey1), nKey1);
  const std::string rver(static_cast<const char*>(pKey2), nKey2);
  (void)notUsed;

  // Early return if versions are equal.
  if (lver == rver) {
    return 0;
  }

  // Get version segments with their nested pieces.
  auto lver_vs = versionSplit(lver);
  auto rver_vs = versionSplit(rver);

  // For each version segment, compare characters between nested pieces.
  auto min_segments = std::min(lver_vs.size(), rver_vs.size());
  for (auto i = 0; i < min_segments; i++) {
    auto min_pieces = std::min(lver_vs[i].size(), rver_vs[i].size());
    for (auto j = 0; j < min_pieces; j++) {
      auto l_is_d = isdigit(lver_vs[i][j][0]);
      auto r_is_d = isdigit(rver_vs[i][j][0]);

      if (l_is_d && r_is_d) {
        // If both pieces of the segment are digits, then numeric compare.
        auto diff = std::stoi(lver_vs[i][j]) - std::stoi(rver_vs[i][j]);
        if (diff != 0) {
          return diff;
        }
      } else if (l_is_d && !r_is_d) {
        // If left piece is a digit, but not the right, then return less than.
        return -1;
      } else if (!l_is_d && r_is_d) {
        // If left piece is not a digit, but the right is, then return greater
        // than.
        return 1;
      } else {
        // If both pieces of the segment are alphabetic, then string compare.
        auto comp = strcmp(lver_vs[i][j].c_str(), rver_vs[i][j].c_str());
        if (comp != 0) {
          return comp;
        }
      }
    }

    // Since all segment pieces up to min(l, r) are equal, check if any more
    // pieces exist, and return if so.
    auto seg_diff = lver_vs[i].size() - rver_vs[i].size();
    if (seg_diff != 0) {
      return seg_diff;
    }
  }

  // Since all version segments up to min(l, r) are equal, check if any more
  // segments exist, and return final result.
  return lver_vs.size() - rver_vs.size();
}

void registerCollations(sqlite3* db) {
  sqlite3_create_collation(db, "version", SQLITE_UTF8, nullptr, versionCollate);
}
} // namespace osquery
