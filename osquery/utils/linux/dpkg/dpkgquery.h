/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

// Acknowledge that the API is volatile; required for the
// headers to work correctly
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/pkg-array.h>
}

#include <memory>

#include <osquery/utils/linux/idpkgquery.h>

namespace osquery {

class DpkgQuery final : public IDpkgQuery {
 public:
  virtual Expected<PackageList, ErrorCode> getPackageList() const override;
  virtual ~DpkgQuery() override;

 private:
  DpkgQuery(const std::string& dpkg_admindir);
  void validateAdminDir(const std::string& path);

  static void packageIteratorCallback(struct pkg_array* array,
                                      struct pkginfo* pkg,
                                      PackageList& package_list);

  friend class IDpkgQuery;
};

} // namespace osquery
