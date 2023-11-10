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

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

extern const std::vector<std::string> kSystemKeychainPaths;
extern const std::vector<std::string> kUserKeychainPaths;

// KeychainMap tracks the temporary copies of keychain files.
// We make a copy of every keychain file before interacting with it via Apple
// APIs.
class KeychainMap {
 public:
  boost::filesystem::path temp_base;
  std::map<boost::filesystem::path, boost::filesystem::path> actual_to_temp;
  std::map<boost::filesystem::path, boost::filesystem::path> temp_to_actual;
  void Insert(boost::filesystem::path actual, boost::filesystem::path temp) {
    actual_to_temp.insert({actual, temp});
    temp_to_actual.insert({temp, actual});
  }
};

void genKeychains(const std::string& path, CFMutableArrayRef& keychains);
std::string getKeychainPath(const SecKeychainItemRef& item);

/// Generate a list of keychain items for a given item type.
CFArrayRef CreateKeychainItems(const std::set<std::string>& paths,
                               const CFTypeRef& item_type,
                               KeychainMap& keychain_map);

std::set<std::string> getKeychainPaths();
}
}
