/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <osquery/filesystem/filesystem.h>

#include "dpkgquery.h"
#include "modstatdb.h"
#include "pkgarray.h"

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/fsys.h>
#include <dpkg/program.h>
#include <dpkg/report.h>
}

namespace osquery {

namespace {

// From the documentation: `installation directory, which refers to the
// directory where packages are to be installed`
const std::string kDpkgInstDir{"/"};

// The `status` file inside a dpkg admindir
const std::string kDpkgStatusFileName{"status"};

} // namespace

Expected<DpkgQuery::PackageList, DpkgQuery::ErrorCode>
DpkgQuery::getPackageList() const {
  auto modstatdb = ModstatDB::open();
  auto pkg_array = PkgArray::create();

  for (auto i = 0; i < pkg_array.get().n_pkgs; i++) {
    auto pkg = pkg_array.get().pkgs[i];

    if (pkg->status == PKG_STAT_NOTINSTALLED) {
      pkg_array.get().pkgs[i] = nullptr;
    }
  }

  PackageList package_list;

  auto L_packageIteratorAdapter =
      [](struct pkg_array* array, struct pkginfo* pkg, void* pkg_data) -> void {
    auto package_list = static_cast<PackageList*>(pkg_data);
    DpkgQuery::packageIteratorCallback(array, pkg, *package_list);
  };

  pkg_array_foreach(&pkg_array.get(), L_packageIteratorAdapter, &package_list);

  if (package_list.empty()) {
    return createError(ErrorCode::NoPackagesFound);
  }

  return package_list;
}

DpkgQuery::~DpkgQuery() {
  dpkg_program_done();
}

DpkgQuery::DpkgQuery(const std::string& dpkg_admindir) {
  validateAdminDir(dpkg_admindir);

  dpkg_program_init("osquery");

  dpkg_fsys_set_dir(kDpkgInstDir.c_str());
  dpkg_db_set_dir(dpkg_admindir.c_str());
}

void DpkgQuery::validateAdminDir(const std::string& path) {
  if (!osquery::isDirectory(path)) {
    throw ErrorCode::InvalidAdminDirPath;
  }

  auto dpkg_status_file_path = path + "/" + kDpkgStatusFileName;
  if (!osquery::isReadable(dpkg_status_file_path)) {
    throw ErrorCode::NotADpkgAdminDir;
  }
}

void DpkgQuery::packageIteratorCallback(struct pkg_array* array,
                                        struct pkginfo* pkg,
                                        PackageList& package_list) {
  Package package;
  package.name = pkg_name(pkg, pnaw_never);
  package.version = versiondescribe(&pkg->installed.version, vdew_nonambig);
  package.arch = dpkg_arch_describe(pkg->installed.arch);
  package.revision = pkg->installed.version.revision;
  package.priority = pkg_priority_name(pkg);

  if (pkg->section != nullptr) {
    package.section = pkg->section;
  }

  if (pkg->installed.installedsize != nullptr) {
    package.size = pkg->installed.installedsize;
  }

  if (pkg->installed.source != nullptr) {
    package.source = pkg->installed.source;
  }

  if (pkg->installed.maintainer != nullptr) {
    package.maintainer = pkg->installed.maintainer;
  }

  {
    std::stringstream buffer;

    buffer << pkg_want_name(pkg) << " " << pkg_eflag_name(pkg) << " "
           << pkg_status_name(pkg);

    package.status = buffer.str();
  }

  package_list.push_back(std::move(package));
}

} // namespace osquery
