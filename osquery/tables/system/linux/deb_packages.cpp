/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>
#include <osquery/tables/system/linux/deb.h>

#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {

static const std::string kDPKGPath{"/var/lib/dpkg"};

void extractDebPackageInfo(const struct pkginfo *pkg, QueryData &results) {
  Row r;

  struct varbuf vb;
  varbuf_init(&vb, 20);

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  const struct fieldinfo* fip = nullptr;
  for (fip = fieldinfos; fip->name; fip++) {
    fip->wcall(&vb, pkg, &pkg->installed, fw_printheader, fip);

    std::string line = vb.string();
    if (!line.empty()) {
      size_t separator_position = line.find(':');

      std::string key = line.substr(0, separator_position);
      std::string value = line.substr(separator_position + 1, line.length());
      auto it = kFieldMappings.find(key);
      if (it != kFieldMappings.end()) {
        boost::algorithm::trim(value);
        r[it->second] = std::move(value);
      }
    }
    varbuf_reset(&vb);
  }
  varbuf_destroy(&vb);

  results.push_back(r);
}

QueryData genDebPackages(QueryContext &context) {
  QueryData results;

  if (!osquery::isDirectory(kDPKGPath)) {
    TLOG << "Cannot find DPKG database: " << kDPKGPath;
    return results;
  }

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  struct pkg_array packages;
  dpkg_setup(&packages);

  for (int i = 0; i < packages.n_pkgs; i++) {
    struct pkginfo *pkg = packages.pkgs[i];
    // Casted to int to allow the older enums that were embeded in the packages
    // struct to be compared
    if (static_cast<int>(pkg->status) ==
        static_cast<int>(PKG_STAT_NOTINSTALLED)) {
      continue;
    }

    extractDebPackageInfo(pkg, results);
  }

  dpkg_teardown(&packages);
  return results;
}
}
}
