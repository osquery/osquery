/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <vector>

#include <osquery/utils/expected/expected.h>

namespace osquery {

class IDpkgQuery {
 public:
  enum class ErrorCode {
    MemoryAllocationFailure,
    InvalidAdminDirPath,
    NotADpkgAdminDir,
    NoPackagesFound,
    PermissionError,
  };

  using Ptr = std::unique_ptr<IDpkgQuery>;

  struct Package final {
    std::string name;
    std::string version;
    std::string source;
    std::string size;
    std::string arch;
    std::string revision;
    std::string status;
    std::string status_string;
    std::string maintainer;
    std::string section;
    std::string priority;
  };

  using PackageList = std::vector<Package>;

  static Expected<Ptr, ErrorCode> create(const std::string& dpkg_admindir);

  virtual Expected<PackageList, ErrorCode> getPackageList() const = 0;

  static std::string getErrorCodeDescription(const ErrorCode& error_code);

  IDpkgQuery() = default;
  virtual ~IDpkgQuery() = default;

  IDpkgQuery(const IDpkgQuery&) = delete;
  IDpkgQuery& operator=(const IDpkgQuery&) = delete;
};

} // namespace osquery
