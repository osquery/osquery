/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/dpkg.h>
#include <dpkg/parsedump.h>
#include <dpkg/pkg-array.h>
}

#include <osquery/query.h>

namespace osquery {
namespace tables {

static const std::string kDPKGPath{"/var/lib/dpkg"};

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
                const struct fieldinfo* fip);

#if !defined(DEB_CONSTS_H)
#define DEB_CONSTS_H 1

/**
* @brief Field names and function references to extract information.
*
* These are taken from lib/dpkg/parse.c, with a slight modification to
* add an fwritefunction for Revision. Additional fields can be taken
* as needed.
*/
extern const std::vector<struct fieldinfo> kfieldinfos;

extern const std::map<std::string, std::string> kFieldMappings;
#endif

/**
* @brief comparator used to sort the packages array.
*/
int pkg_sorter(const void* a, const void* b);

/*
* @brief Initialize dpkg and load packages into memory
*/
void dpkg_setup(struct pkg_array* packages);

/**
* @brief Clean up after dpkg operations
*/
void dpkg_teardown(struct pkg_array* packages);
}
}
