/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif
#ifdef WIN32
#pragma warning(pop)
#endif

#include <osquery/filesystem/filesystem.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/tryto.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const fs::path& sub_dir);

/// A helper check to rename bool-type values as 1 or 0.
inline void jsonBoolAsInt(std::string& s) {
  auto expected = tryTo<bool>(s);
  if (expected.isValue()) {
    s = expected.get() ? "1" : "0";
  }
}
}
}
