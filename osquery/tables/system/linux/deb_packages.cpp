/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

#include <boost/algorithm/string.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/dpkg.h>
#include <dpkg/parsedump.h>
#include <dpkg/pkg-array.h>
}

namespace osquery {
namespace tables {

static const std::string kDPKGPath{"/var/lib/dpkg"};

/// A comparator used to sort the packages array.
int pkg_sorter(const void* a, const void* b) {
  const struct pkginfo* pa = *(const struct pkginfo**)a;
  const struct pkginfo* pb = *(const struct pkginfo**)b;
  const char* arch_a = pa->installed.arch->name;
  const char* arch_b = pb->installed.arch->name;

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
void w_revision(struct varbuf* vb,
                const struct pkginfo* pkg,
                const struct pkgbin* pkgbin,
                enum fwriteflags flags,
                const struct fieldinfo* fip) {
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
void dpkg_setup(struct pkg_array* packages) {
  dpkg_set_progname("osquery");
  push_error_context();

  dpkg_db_set_dir(kDPKGPath.c_str());
  modstatdb_init();
  modstatdb_open(msdbrw_readonly);

  pkg_array_init_from_db(packages);
  pkg_array_sort(packages, pkg_sorter);
}

/**
 * @brief Clean up after dpkg operations
 */
void dpkg_teardown(struct pkg_array* packages) {
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
    {"Revision", "revision"},
    {"Status", "status"},
    {"Maintainer", "maintainer"},
    {"Section", "section"},
    {"Priority", "priority"}};

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
    {FIELD("Status"), f_status, w_status, 0},
    {FIELD("Maintainer"), f_charfield, w_charfield, PKGIFPOFF(maintainer)},
    {FIELD("Priority"), f_priority, w_priority, 0},
    {FIELD("Section"), f_section, w_section, 0},
    {}};

void extractDebPackageInfo(const struct pkginfo* pkg, QueryData& results) {
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

  if (r.find("size") == r.end()) {
    // Possible meta-package without an installed-size.
    r["size"] = "0";
  }

  r["pid_with_namespace"] = "0";

  results.push_back(r);
}

QueryData genDebPackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  if (!osquery::isDirectory(kDPKGPath)) {
    logger.vlog(1, "Cannot find DPKG database: " + kDPKGPath);
    return results;
  }

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  struct pkg_array packages;
  dpkg_setup(&packages);

  for (int i = 0; i < packages.n_pkgs; i++) {
    struct pkginfo* pkg = packages.pkgs[i];
    // Casted to int to allow the older enums that were embedded in the packages
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

QueryData genDebPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "deb_packages", genDebPackagesImpl);
  } else {
    GLOGLogger logger;
    return genDebPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
