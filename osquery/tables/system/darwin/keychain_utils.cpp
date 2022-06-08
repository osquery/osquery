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
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/utils/conversions/join.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemKeychainPaths = {
    "/System/Library/Keychains",
    "/Library/Keychains",
};

const std::vector<std::string> kUserKeychainPaths = {
    "/Library/Keychains",
};

void genKeychains(const std::string& path, CFMutableArrayRef& keychains) {
  std::vector<std::string> paths;

  // Support both a directory and explicit path search.
  if (isDirectory(path).ok()) {
    // Try to list every file in the given keychain search path.
    if (!listFilesInDirectory(path, paths).ok()) {
      return;
    }
  } else {
    // The explicit path search comes from a query predicate.
    paths.push_back(path);
  }

  for (const auto& keychain_path : paths) {
    SecKeychainRef keychain = nullptr;
    auto status = SecKeychainOpen(keychain_path.c_str(), &keychain);
    if (status == 0 && keychain != nullptr) {
      CFArrayAppendValue(keychains, keychain);
    }
  }
}

std::string getKeychainPath(const SecKeychainItemRef& item) {
  SecKeychainRef keychain = nullptr;
  std::string path;
  auto status = SecKeychainItemCopyKeychain(item, &keychain);
  if (keychain == nullptr || status != errSecSuccess) {
    // Unhandled error, cannot get the keychain reference from certificate.
    return path;
  }

  UInt32 path_size = 1024;
  char keychain_path[1024] = {0};
  status = SecKeychainGetPath(keychain, &path_size, keychain_path);
  if (status != errSecSuccess || (path_size > 0 && keychain_path[0] != 0)) {
    path = std::string(keychain_path);
  }

  CFRelease(keychain);
  return path;
}

CFArrayRef CreateKeychainItems(const std::set<std::string>& paths,
                               const CFTypeRef& item_type) {
  auto keychains = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
  for (const auto& path : paths) {
    genKeychains(path, keychains);
  }

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

  CFArrayRef keychain_certs;
  auto status = SecItemCopyMatching(query, (CFTypeRef*)&keychain_certs);
  CFRelease(query);

  // Release each keychain search path.
  CFRelease(keychains);

  if (status != errSecSuccess) {
    return nullptr;
  }

  return keychain_certs;
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
} // namespace tables
} // namespace osquery
