/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif
#include <boost/property_tree/json_parser.hpp>
#ifdef WIN32
#pragma warning(pop)
#endif

#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const fs::path& sub_dir);

/// A helper check to rename bool-type values as 1 or 0.
inline void jsonBoolAsInt(std::string& s) {
  if (s == "true" || s == "YES" || s == "Yes") {
    s = "1";
  } else if (s == "false" || s == "NO" || s == "No") {
    s = "0";
  }
}
}
}
