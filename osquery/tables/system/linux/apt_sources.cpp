/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// libapt-pkg uses the 'DEBUG' symbol as an enum.
#ifdef DEBUG
#undef DEBUG
#define __DEBUG
#endif

#include <apt-pkg/init.h>
#include <apt-pkg/cachefile.h>

#ifdef __DEBUG
#define DEBUG
#endif

#include <osquery/system.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
* @brief Empty the configuration out of memory when we're done with it
*
* Newer versions of libapt-pkg provide this as _config->Clear(), brought
* forward for compatibility with older library versions.
*/
void closeConfig() {
  const Configuration::Item* Top = _config->Tree(0);
  while (Top != 0) {
    _config->Clear(Top->FullTag());
    Top = Top->Next;
  }
}

bool isFieldOkay(const char* fieldValue) {
  // Ensure the value is initialized so we don't segfault
  return (fieldValue != 0 && fieldValue[0] != 0);
}

void extractAptSourceInfo(pkgCache::PkgFileIterator src,
                          const pkgIndexFile* pkgIndex,
                          QueryData& results) {
  Row r;

  r["name"] = pkgIndex->Describe(true);

  // If we don't pass it a path to construct, it will
  // just return the base URI of the repo
  r["base_uri"] = pkgIndex->ArchiveURI("");

  if (isFieldOkay(src.FileName()))
    r["package_cache_file"] = src.FileName();
  if (isFieldOkay(src.Archive()))
    r["release"] = src.Archive();
  if (isFieldOkay(src.Component()))
    r["component"] = src.Component();
  if (isFieldOkay(src.Version()))
    r["version"] = src.Version();
  if (isFieldOkay(src.Origin()))
    r["maintainer"] = src.Origin();
  if (isFieldOkay(src.Label()))
    r["label"] = src.Label();
  if (isFieldOkay(src.Site()))
    r["site"] = src.Site();

  results.push_back(r);
}

QueryData genAptSrcs(QueryContext& context) {
  QueryData results;

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Load our apt configuration into memory
  // Note: _config comes from apt-pkg/configuration.h
  //       _system comes from apt-pkg/pkgsystem.h
  pkgInitConfig(*_config);
  pkgInitSystem(*_config, _system);

  pkgCacheFile cache_file;
  pkgCache* cache = cache_file.GetPkgCache();
  pkgSourceList* src_list = cache_file.GetSourceList();
  if (cache == nullptr || src_list == nullptr) {
    cache_file.Close();
    closeConfig();
    return results;
  }

  // For each apt cache file that contains packages
  for (pkgCache::PkgFileIterator file = cache->FileBegin(); file && !file.end();
       ++file) {
    // Locate the associated index files to ensure the repository is installed
    pkgIndexFile* pkgIndex;
    if (!src_list->FindIndex(file, pkgIndex)) {
      continue;
    }

    extractAptSourceInfo(file, pkgIndex, results);
  }

  // Cleanup
  cache_file.Close();
  closeConfig();

  return results;
}
}
}
