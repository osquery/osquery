/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <osquery/utils/linux/idpkgquery.h>

#include "dpkgquery.h"
#include "idpkgquery.h"

namespace osquery {

namespace {

const std::unordered_map<IDpkgQuery::ErrorCode, std::string>
    kErrorDescriptionMap = {
        {IDpkgQuery::ErrorCode::MemoryAllocationFailure,
         "MemoryAllocationFailure"},
        {IDpkgQuery::ErrorCode::InvalidAdminDirPath, "InvalidAdminDirPath"},
        {IDpkgQuery::ErrorCode::NotADpkgAdminDir, "NotADpkgAdminDir"},
        {IDpkgQuery::ErrorCode::NoPackagesFound, "NoPackagesFound"},
        {IDpkgQuery::ErrorCode::PermissionError, "PermissionError"},
};

}

Expected<IDpkgQuery::Ptr, IDpkgQuery::ErrorCode> IDpkgQuery::create(
    const std::string& dpkg_admindir) {
  try {
    return Ptr(new DpkgQuery(dpkg_admindir));

  } catch (const IDpkgQuery::ErrorCode& error_code) {
    return createError(error_code);

  } catch (const std::bad_alloc&) {
    return createError(IDpkgQuery::ErrorCode::MemoryAllocationFailure);
  }
}

std::string IDpkgQuery::getErrorCodeDescription(const ErrorCode& error_code) {
  std::string description;

  auto description_it = kErrorDescriptionMap.find(error_code);
  if (description_it == kErrorDescriptionMap.end()) {
    description =
        "Unknown error code: " + std::to_string(static_cast<int>(error_code));

  } else {
    description = description_it->second;
  }

  return description;
}

} // namespace osquery
