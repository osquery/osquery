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

void genKeychains(const std::string& path, CFMutableArrayRef& keychains);
std::string getKeychainPath(const SecKeychainItemRef& item);

/// Generate a list of keychain items for a given item type.
CFArrayRef CreateKeychainItems(const std::set<std::string>& paths,
                               const CFTypeRef& item_type);

std::set<std::string> getKeychainPaths();
}
}
