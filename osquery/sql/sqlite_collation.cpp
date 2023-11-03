/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <sqlite3.h>

namespace osquery {
/**
 * @brief Compares the position of epoch delimiter between two versions.
 * Return difference of epoch segment length if both versions have epoch.
 * Return 1 if left version has epoch but not the right.
 * Return -1 if right version has epoch but not the left.
 * Return 0 if epoch doesn't exist in either version.
 */
static int compareEpoch(int lLen,
                        const char* lVer,
                        int rLen,
                        const char* rVer) {
  auto lEpoch = strcspn(lVer, ":");
  auto rEpoch = strcspn(rVer, ":");

  if (lEpoch != lLen && rEpoch != rLen) {
    return lEpoch - rEpoch;
  } else if (lEpoch != lLen && rEpoch == rLen) {
    return 1;
  } else if (lEpoch == lLen && rEpoch != rLen) {
    return -1;
  }

  return 0;
}

/**
 * @brief Check if character is defined as a delimiter: `~-^.:`
 */
static bool isDelimiter(int c) {
  switch (c) {
  case 126:
  case 45:
  case 94:
  case 46:
  case 58:
    return true;
  default:
    return false;
  }
}

/**
 * @brief Set the delimiter precedence if they should compare against each
 * other. Delimiters: `~-^.:`
 */
static int delimiterPrecedence(int d) {
  switch (d) {
  case 126:
    return 1;
  case 45:
    return 2;
  case 94:
    return 3;
  case 46:
    return 4;
  case 58:
    return 5;
  default:
    return 0;
  }
}

/**
 * @brief Return remainder sort order, or return the version length difference.
 */
static int compareRemainder(int lLen,
                            const char* lVer,
                            int rLen,
                            const char* rVer,
                            int pos,
                            int diff,
                            const bool comp_remaining,
                            const bool remainder_precedence) {
  // This supports linux package versioning sort order when a tilde should be
  // less than, a caret should be greater than, and a hyphen should be equal.
  //
  // When remainder_precedence = true, this will return the segment value diff
  // if the last compared character was numeric, otherwise it falls through to
  // return length diff.
  //
  // When remainder_precedence = false, this will return the segment value diff
  // if there is any before falling through to return length diff.
  if (comp_remaining) {
    if (lLen == pos) {
      switch (int(rVer[pos])) {
      case 126:
        return 1;
      case 45:
        return 0;
      case 94:
        return -1;
      default:
        if (diff != 0 && (!remainder_precedence || !isdigit(lVer[pos - 1]))) {
          return diff;
        }
      }
    }

    if (rLen == pos) {
      switch (int(lVer[pos])) {
      case 126:
        return -1;
      case 45:
        return 0;
      case 94:
        return 1;
      default:
        if (diff != 0 && (!remainder_precedence || !isdigit(rVer[pos - 1]))) {
          return diff;
        }
      }
    }
  }

  return lLen - rLen;
}

/**
 * @brief Compares two versions strings against each other.
 * Return 0 if the versions should evaluate as equal.
 * Return negative int if the left string is less than the right.
 * Return positive int if the left string is greater than the right.
 */
static int versionCompare(int lLen,
                          const void* lVersion,
                          int rLen,
                          const void* rVersion,
                          const bool epoch = false,
                          const bool delim_precedence = false,
                          const bool comp_remaining = false,
                          const bool remainder_precedence = false) {
  const char* lVer = static_cast<const char*>(lVersion);
  const char* rVer = static_cast<const char*>(rVersion);

  // Early return if versions are equal.
  if (lVer == rVer) {
    return 0;
  }

  // Check for and return difference in epoch position.
  if (epoch) {
    auto epoch_diff = compareEpoch(lLen, lVer, rLen, rVer);
    if (epoch_diff != 0) {
      return epoch_diff;
    }
  }

  int first_diff = 0;
  auto min = std::min(lLen, rLen);
  for (auto i = 0; i < min; i++) {
    auto lVal = int(lVer[i]);
    auto rVal = int(rVer[i]);
    auto lDelim = isDelimiter(lVal);
    auto rDelim = isDelimiter(rVal);

    // Until we hit a delimiter, we will compare the ASCII values of each
    // character, and store the first difference of this segment.
    if (!lDelim && !rDelim) {
      first_diff = first_diff == 0 ? lVal - rVal : first_diff;
      continue;
    } else if (lDelim && !rDelim) {
      return -1;
    } else if (!lDelim && rDelim) {
      return 1;
    }

    // If we've hit delimiters in both versions, then return the first value
    // difference in this segment.
    if (first_diff != 0) {
      return first_diff;
    }

    // Check for and return difference in delimiter precedence.
    if (delim_precedence) {
      auto delim_diff = delimiterPrecedence(lVal) - delimiterPrecedence(rVal);
      if (delim_diff != 0) {
        return delim_diff;
      }
    }
  }

  // If the versions are the same length, then return the first difference in
  // the final segment.
  if (lLen == rLen) {
    return first_diff;
  }

  return compareRemainder(lLen,
                          lVer,
                          rLen,
                          rVer,
                          min,
                          first_diff,
                          comp_remaining,
                          remainder_precedence);
}

/**
 * @brief Collate generic version strings.
 */
static int versionCollate(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  (void)notUsed;
  return versionCompare(nKey1, pKey1, nKey2, pKey2, false, false, false, false);
}

/**
 * @brief Collate arch package version strings.
 */
static int versionCollateARCH(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  (void)notUsed;
  return versionCompare(nKey1, pKey1, nKey2, pKey2, true, false, true, true);
}

/**
 * @brief Collate deb package version strings.
 */
static int versionCollateDPKG(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  (void)notUsed;
  return versionCompare(nKey1, pKey1, nKey2, pKey2, true, true, false, false);
}

/**
 * @brief Collate rhel package version strings.
 */
static int versionCollateRHEL(
    void* notUsed, int nKey1, const void* pKey1, int nKey2, const void* pKey2) {
  (void)notUsed;
  return versionCompare(nKey1, pKey1, nKey2, pKey2, true, true, true, false);
}

void registerCollations(sqlite3* db) {
  sqlite3_create_collation(db, "version", SQLITE_UTF8, nullptr, versionCollate);
  sqlite3_create_collation(
      db, "version_arch", SQLITE_UTF8, nullptr, versionCollateARCH);
  sqlite3_create_collation(
      db, "version_dpkg", SQLITE_UTF8, nullptr, versionCollateDPKG);
  sqlite3_create_collation(
      db, "version_rhel", SQLITE_UTF8, nullptr, versionCollateRHEL);
}
} // namespace osquery
