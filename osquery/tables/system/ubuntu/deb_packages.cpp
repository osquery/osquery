/*
*  Copyright (c) 2014, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <boost/algorithm/string.hpp>
#include <osquery/tables.h>

// see README.api of libdpkg-dev
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>

// copy pasted from dpkg-db.h
// these enums are inside struct pkginfo and are not visible for other headers
enum pkgwant {
  want_unknown,
  want_install,
  want_hold,
  want_deinstall,
  want_purge,
  // Not allowed except as special sentinel value in some places.
  want_sentinel,
} want;

// The error flag bitmask.
enum pkgeflag {
  eflag_ok = 0,
  eflag_reinstreq = 1,
} eflag;

enum pkgstatus {
  stat_notinstalled,
  stat_configfiles,
  stat_halfinstalled,
  stat_unpacked,
  stat_halfconfigured,
  stat_triggersawaited,
  stat_triggerspending,
  stat_installed
} status;

#include <dpkg/dpkg.h>
#include <dpkg/pkg-array.h>
#include <dpkg/parsedump.h>
}

namespace osquery {
namespace tables {

/**
* @brief A comparator used to sort the packages array
*/
int pkg_sorter(const void *a, const void *b) {
  const struct pkginfo *pa = *(const struct pkginfo **)a;
  const struct pkginfo *pb = *(const struct pkginfo **)b;
  const char *arch_a = pa->installed.arch->name;
  const char *arch_b = pb->installed.arch->name;
  int res;

  res = strcmp(pa->set->name, pb->set->name);
  if (res) {
    return res;
  }

  if (pa->installed.arch == pb->installed.arch) {
    return 0;
  }

  return strcmp(arch_a, arch_b);
}

/**
* @brief A field extractor to fetch the revision of a package
*
* dpkg tracks the revision as part of version, but we need to
* provde our own fwritefunction for fieldinfos to extract it.
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
* @brief Field names and function references to extract information
*
* These are taken from lib/dpkg/parse.c, with a slight modification to
* add an fwritefunction for Revision. Additional fields can be taken
* as needed.
*/
const struct fieldinfo fieldinfos[] = {
    {"Package", f_name, w_name},
    {"Installed-Size", f_charfield, w_charfield, PKGIFPOFF(installedsize)},
    {"Architecture", f_architecture, w_architecture},
    {"Source", f_charfield, w_charfield, PKGIFPOFF(source)},
    {"Version", f_version, w_version, PKGIFPOFF(version)},
    {"Revision", f_revision, w_revision},
    {NULL}};

void extractDebPackageInfo(const struct pkginfo *pkg, QueryData &results) {
  Row r;
  const struct fieldinfo *fip;
  struct varbuf vb;
  varbuf_init(&vb, 20);

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  for (fip = fieldinfos; fip->name; fip++) {
    fip->wcall(&vb, pkg, &pkg->installed, fw_printheader, fip);

    std::string line = vb.string();
    if (!line.empty()) {
      std::size_t separator_position = line.find(':');
      std::string key = line.substr(0, separator_position);
      std::string value = line.substr(separator_position + 1, line.length());
      auto it = kFieldMappings.find(key);
      if (it != kFieldMappings.end()) {
        boost::algorithm::trim(value);
        r[it->second] = value;
      }
    }
    varbuf_reset(&vb);
  }
  varbuf_destroy(&vb);

  results.push_back(r);
}

QueryData genDebs(QueryContext &context) {
  QueryData results;

  struct pkg_array packages;
  dpkg_setup(&packages);
  for (int i = 0; i < packages.n_pkgs; i++) {
    struct pkginfo *pkg = packages.pkgs[i];
    if (pkg->status == pkg->stat_notinstalled) {
      continue;
    }

    extractDebPackageInfo(pkg, results);
  }

  dpkg_teardown(&packages);
  return results;
}
}
}
