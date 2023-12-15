/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/opensslv.h>
#include <openssl/x509.h>

#include <iomanip>
#include <string>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/utils/conversions/join.h>

#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

FLAG(bool,
     keychain_access_cache,
     true,
     "Use a cache for keychain accesses (default true)")
FLAG(uint32,
     keychain_access_interval,
     5,
     "Minimum minutes required between keychain accesses. Keychain cache must "
     "be enabled to use")

KeychainCache keychainCache = KeychainCache();
std::mutex keychainMutex;

const std::vector<std::string> kSystemKeychainPaths = {
    "/System/Library/Keychains",
    "/Library/Keychains",
};

const std::vector<std::string> kUserKeychainPaths = {
    "/Library/Keychains",
};

std::set<std::string> expandPaths(const std::set<std::string>& paths) {
  std::set<std::string> expanded_paths;
  for (const auto& path : paths) {
    // Support both a directory and explicit path search.
    if (isDirectory(path).ok()) {
      // Try to list every file in the given keychain search path.
      std::vector<std::string> directory_paths;
      if (!listFilesInDirectory(path, directory_paths).ok()) {
        continue;
      }
      expanded_paths.insert(directory_paths.cbegin(), directory_paths.cend());
    } else {
      // The explicit path search comes from a query predicate.
      expanded_paths.insert(path);
    }
  }
  return expanded_paths;
}

std::string getKeychainPath(const SecKeychainItemRef& item) {
  SecKeychainRef keychain = nullptr;
  std::string path;
  OSStatus status;
  OSQUERY_USE_DEPRECATED(status = SecKeychainItemCopyKeychain(item, &keychain));
  if (keychain == nullptr || status != errSecSuccess) {
    // Unhandled error, cannot get the keychain reference from certificate.
    return path;
  }

  UInt32 path_size = 1024;
  char keychain_path[1024] = {0};
  OSQUERY_USE_DEPRECATED(
      status = SecKeychainGetPath(keychain, &path_size, keychain_path));
  if (status != errSecSuccess || (path_size > 0 && keychain_path[0] != 0)) {
    path = std::string(keychain_path);
  }

  CFRelease(keychain);
  return path;
}

CFArrayRef CreateKeychainItems(CFMutableArrayRef keychains,
                               const CFTypeRef& item_type) {
  CFMutableDictionaryRef query;
  query = CFDictionaryCreateMutable(nullptr,
                                    0,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, item_type);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  // This can be added to restrict results to x509v3
  // CFDictionaryAddValue(query, kSecAttrCertificateType, 0x03);
  CFDictionaryAddValue(query, kSecMatchSearchList, keychains);
  CFDictionaryAddValue(query, kSecAttrCanVerify, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);

  CFArrayRef keychain_items;
  auto status = SecItemCopyMatching(query, (CFTypeRef*)&keychain_items);
  CFRelease(query);

  if (status != errSecSuccess) {
    return nullptr;
  }

  return keychain_items;
}

std::set<std::string> getKeychainPaths() {
  std::set<std::string> keychain_paths;

  for (const auto& path : kSystemKeychainPaths) {
    keychain_paths.insert(path);
  }

  auto homes = getHomeDirectories();
  for (const auto& dir : homes) {
    for (const auto& keychains_dir : kUserKeychainPaths) {
      keychain_paths.insert((dir / keychains_dir).string());
    }
  }

  return keychain_paths;
}

bool KeychainCache::Read(const boost::filesystem::path& path,
                         const KeychainTable table,
                         std::string& hash,
                         QueryData& results,
                         bool& err) {
  if (!FLAGS_keychain_access_cache) {
    // Don't use the cache.
    return false;
  }

  // Get hash of the file.
  hash = hashFromFile(HASH_TYPE_SHA256, path.string());
  if (hash.empty()) {
    err = true;
    return false;
  }

  // Check the cache.
  auto it = this->cache.find(std::make_pair(path, table));
  if (it == this->cache.end()) {
    // Cache miss. This always occurs on the first read.
    return false;
  }
  KeychainCacheEntry& entry = it->second;
  if (entry.hash == hash) {
    // Exact cache hit. Append results from cache.
    results.insert(results.end(), entry.results.begin(), entry.results.end());
    return true;
  }
  TLOG << "Previous hash did not match. Modified file: " << path.string();

  // Check the read interval -- are we allowed to update the cache. If not, we
  // return the cached results.
  if (std::chrono::system_clock::now() >=
      entry.timestamp + std::chrono::minutes(FLAGS_keychain_access_interval)) {
    return false;
  }
  TLOG << "Access to keychain file throttled. Returning previous results for: "
       << path.string();
  results.insert(results.end(), entry.results.begin(), entry.results.end());
  return true;
}

void KeychainCache::Write(const boost::filesystem::path& path,
                          const KeychainTable table,
                          const std::string& hash,
                          const QueryData& results) {
  if (!FLAGS_keychain_access_cache) {
    // Don't use the cache.
    return;
  }

  // Make entry to insert.
  KeychainCacheEntry entry;
  entry.timestamp = std::chrono::system_clock::now();
  entry.hash = hash;
  entry.results = results;

  std::pair<boost::filesystem::path, KeychainTable> key =
      std::make_pair(path, table);
  this->cache.insert_or_assign(key, entry);
}

} // namespace tables
} // namespace osquery
