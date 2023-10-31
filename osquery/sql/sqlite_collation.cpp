/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>

#include <sqlite3.h>

namespace osquery {
/**
 * @brief Splits a version into segments based on the input pattern sub-matches.
 */
static std::vector<std::string> versionSplit(std::string_view version,
                                             std::regex pattern) {
  std::vector<std::string> result;
  std::cregex_token_iterator iter_begin(
      version.begin(), version.end(), pattern);
  std::cregex_token_iterator iter_end;

  while (iter_begin != iter_end) {
    result.push_back(*iter_begin++);
  }

  return result;
}

/**
 * @brief Compares ASCII character values of left and right version sequences.
 * Returns 0 if they are equal, negative int if left is less than right, or
 * positive int is left is greater than right.
 */
static int versionCompare(int lLen,
                          const char* lVer,
                          int rLen,
                          const char* rVer) {
  if (lVer == rVer) {
    // Early return if version sequences are equal.
    return 0;
  }

  auto len_diff = lLen - rLen;
  if (len_diff != 0) {
    // Early return if version sequences are not equal size.
    return len_diff;
  }

  for (auto i = 0; i < lLen; i++) {
    // Compare ASCII character value of each positional character.
    auto l_pos_val = int(lVer[i]);
    auto r_pos_val = int(rVer[i]);

    auto val_diff = l_pos_val - r_pos_val;
    if (val_diff != 0) {
      return val_diff;
    }
  }

  return 0;
}

/**
 * @brief Creates and compares version segments. Version segments are split
 * based on input regex pattern sub-matches.
 */
static int versionSegment(std::string_view lVer,
                          std::string_view rVer,
                          std::regex pattern) {
  auto lSegments = versionSplit(lVer, pattern);
  auto rSegments = versionSplit(rVer, pattern);
  auto lSegCount = lSegments.size();
  auto rSegCount = rSegments.size();

  auto minSegments = std::min(lSegCount, rSegCount);
  for (auto i = 0; i < minSegments; i++) {
    // Compare each version segment.
    auto lSeg = lSegments[i].c_str();
    auto rSeg = rSegments[i].c_str();

    auto rc = versionCompare(strlen(lSeg), lSeg, strlen(rSeg), rSeg);
    if (rc != 0) {
      return rc;
    }
  }

  // Return the difference of version segment counts if all positional character
  // values are equal to their respective segment.
  return lSegCount - rSegCount;
}

/**
 * @brief Collate version strings. This is a simple left to right ASCII value
 * comparison. This is not recommended to call if a delimiter is required.
 */
static int versionCollate(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  (void)notUsed;
  return versionCompare(nKey1,
                        static_cast<const char*>(pKey1),
                        nKey2,
                        static_cast<const char*>(pKey2));
}

/**
 * @brief Collate version strings. Compares alphanumeric characters by version
 * segments. This is recommended to call if any special characters should split
 * off a version into a segment to compare.
 */
static int versionCollateAlphaNum(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  std::string_view lVer(static_cast<const char*>(pKey1), nKey1);
  std::string_view rVer(static_cast<const char*>(pKey2), nKey2);
  (void)notUsed;
  std::regex re("[\\da-zA-Z]+");
  return versionSegment(lVer, rVer, re);
}

/**
 * @brief Collate version strings. Compares alphanumeric characters by version
 * segments. This is recommended to call if periods should split off a version
 * into a segment to compare.
 */
static int versionCollatePeriod(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  std::string_view lVer(static_cast<const char*>(pKey1), nKey1);
  std::string_view rVer(static_cast<const char*>(pKey2), nKey2);
  (void)notUsed;
  std::regex re("[^\\.]+");
  return versionSegment(lVer, rVer, re);
}

void registerCollations(sqlite3* db) {
  sqlite3_create_collation(db, "version", SQLITE_UTF8, nullptr, versionCollate);
  sqlite3_create_collation(
      db, "version_alnum", SQLITE_UTF8, nullptr, versionCollateAlphaNum);
  sqlite3_create_collation(
      db, "version_period", SQLITE_UTF8, nullptr, versionCollatePeriod);
}
} // namespace osquery
