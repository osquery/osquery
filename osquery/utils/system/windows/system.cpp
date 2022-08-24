/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "system.h"

#include <osquery/utils/conversions/windows/strings.h>

#include <vector>

namespace osquery {
std::string getHostname() {
  DWORD size = 0;
  if (0 == GetComputerNameW(nullptr, &size)) {
    std::vector<WCHAR> computer_name(size, 0);
    GetComputerNameW(computer_name.data(), &size);
    return wstringToString(computer_name.data());
  }

  return {};
}

std::string getFqdn() {
  DWORD size = 0;
  if (0 == GetComputerNameExW(ComputerNameDnsFullyQualified, nullptr, &size)) {
    std::vector<WCHAR> fqdn(size, 0);
    GetComputerNameExW(ComputerNameDnsFullyQualified, fqdn.data(), &size);
    return wstringToString(fqdn.data());
  }

  return {};
}
} // namespace osquery
