/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/dpkg.h>
#include <dpkg/pkg-array.h>
#include <dpkg/parsedump.h>
}

#include <boost/algorithm/string.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION_deb_packages
#include <generated/tables/tbl_deb_packages_defs.hpp>

namespace osquery {
namespace tables {

static const std::string kDPKGPath{"/var/lib/dpkg"};

/// A comparator used to sort the packages array.
int pkg_sorter(const void *a, const void *b) {
  const struct pkginfo *pa = *(const struct pkginfo **)a;
  const struct pkginfo *pb = *(const struct pkginfo **)b;
  const char *arch_a = pa->installed.arch->name;
  const char *arch_b = pb->installed.arch->name;

  int res = strcmp(pa->set->name, pb->set->name);
  if (res != 0) {
    return res;
  }

  if (pa->installed.arch == pb->installed.arch) {
    return 0;
  }

  return strcmp(arch_a, arch_b);
}

/**
 * @brief A field extractor to fetch the revision of a package.
 *
 * dpkg tracks the revision as part of version, but we need to provide our own
 * fwritefunction for fieldinfos to extract it.
 */
void w_revision(struct varbuf *vb,
                const struct pkginfo *pkg,
                const struct pkgbin *pkgbin,
                enum fwriteflags flags,
                const struct fieldinfo *fip) {
  if (flags & fw_printheader) {
    varbuf_add_str(vb, "Revision: ");
  }
  varbuf_add_str(vb, pkgbin->version.revision);
  if (flags & fw_printheader) {
    varbuf_add_char(vb, '\n');
  }
}

/**
* @brief Initialize dpkg and load packages into memory
*/
void dpkg_setup(struct pkg_array *packages) {
  dpkg_set_progname("osquery");
  push_error_context();

  dpkg_db_set_dir("/var/lib/dpkg/");
  modstatdb_init();
  modstatdb_open(msdbrw_readonly);

  pkg_array_init_from_db(packages);
  pkg_array_sort(packages, pkg_sorter);
}

/**
* @brief Clean up after dpkg operations
*/
void dpkg_teardown(struct pkg_array *packages) {
  pkg_array_destroy(packages);

  pkg_db_reset();
  modstatdb_done();

  pop_error_context(ehflag_normaltidy);
}

const std::map<std::string, std::string> kFieldMappings = {
    {"Package", "name"},
    {"Version", "version"},
    {"Installed-Size", "size"},
    {"Architecture", "arch"},
    {"Source", "source"},
    {"Revision", "revision"}};

/**
* @brief Field names and function references to extract information.
*
* These are taken from lib/dpkg/parse.c, with a slight modification to
* add an fwritefunction for Revision. Additional fields can be taken
* as needed.
*/
const struct fieldinfo fieldinfos[] = {
    {FIELD("Package"), f_name, w_name, 0},
    {FIELD("Installed-Size"),
     f_charfield,
     w_charfield,
     PKGIFPOFF(installedsize)},
    {FIELD("Architecture"), f_architecture, w_architecture, 0},
    {FIELD("Source"), f_charfield, w_charfield, PKGIFPOFF(source)},
    {FIELD("Version"), f_version, w_version, PKGIFPOFF(version)},
    {FIELD("Revision"), f_revision, w_revision, 0},
    {}};

void extractDebPackageInfo(const struct pkginfo *pkg, QueryData &results) {
  Row r;

  struct varbuf vb;
  varbuf_init(&vb, 20);

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  const struct fieldinfo *fip = nullptr;
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
