/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <set>
#include <vector>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

extern const std::vector<std::string> kSystemKeychainPaths;
extern const std::vector<std::string> kUserKeychainPaths;

// Declare keychain flags. They are defined in keychain_utils.cpp.
DECLARE_bool(keychain_access_cache); // enable flag
DECLARE_uint32(keychain_access_interval); // throttling flag

// The tables supported by Keychain Cache
enum class KeychainTable { CERTIFICATES, KEYCHAIN_ACLS, KEYCHAIN_ITEMS };

// The KeychainCache caches results associated with keychain files,
// and throttles access to these files.
class KeychainCache {
 private:
  // KeychainCacheEntry contains cache metadata and cached results
  // for a single keychain file.
  class KeychainCacheEntry {
   public:
    std::chrono::system_clock::time_point timestamp; // time of last access
    std::string hash; // sha256 keychain file hash
    QueryData results; // the cached results
  };
  std::map<std::pair<boost::filesystem::path, KeychainTable>,
           KeychainCacheEntry>
      cache;

 public:
  // Read checks the hash and returns 1 for a cache hit or 0 for a cache miss.
  // If hit, results are populated. hash is the file hash
  bool Read(const boost::filesystem::path& path,
            KeychainTable table,
            std::string& hash,
            QueryData& results,
            bool& err);
  // Write a cache entry.
  void Write(const boost::filesystem::path& path,
             KeychainTable table,
             const std::string& hash,
             const QueryData& results);
  size_t Size() {
    return cache.size();
  }
};
extern KeychainCache keychainCache;
extern std::mutex keychainMutex;

// Expand paths to individual files
std::set<std::string> expandPaths(const std::set<std::string>& paths);

std::string getKeychainPath(const SecKeychainItemRef& item);

/// Generate a list of keychain items for a given item type.
CFArrayRef CreateKeychainItems(CFMutableArrayRef keychains,
                               const CFTypeRef& item_type);

std::set<std::string> getKeychainPaths();
}
}
