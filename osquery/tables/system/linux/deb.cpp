/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables/system/linux/deb.h>

namespace osquery {
namespace tables {

const std::vector<struct fieldinfo> fieldinfos = {
    {FIELD("Package"), f_name, w_name, 0},
    {FIELD("Installed-Size"),
     f_charfield,
     w_charfield,
     PKGIFPOFF(installedsize)},
    {FIELD("Architecture"), f_architecture, w_architecture, 0},
    {FIELD("Source"), f_charfield, w_charfield, PKGIFPOFF(source)},
    {FIELD("Version"), f_version, w_version, PKGIFPOFF(version)},
    {FIELD("Revision"), f_revision, w_revision, 0}};

const std::map<std::string, std::string> kFieldMappings = {
    {"Package", "name"},
    {"Version", "version"},
    {"Installed-Size", "size"},
    {"Architecture", "arch"},
    {"Source", "source"},
    {"Revision", "revision"}};


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

void dpkg_setup(struct pkg_array* packages) {
  dpkg_set_progname("osquery");
  push_error_context();

  dpkg_db_set_dir("/var/lib/dpkg/");
  modstatdb_init();
  modstatdb_open(msdbrw_readonly);

  pkg_array_init_from_db(packages);
  pkg_array_sort(packages, pkg_sorter);
}

void dpkg_teardown(struct pkg_array* packages) {
  pkg_array_destroy(packages);

  pkg_db_reset();
  modstatdb_done();

  pop_error_context(ehflag_normaltidy);
}
}
}
