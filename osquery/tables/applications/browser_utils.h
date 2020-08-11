/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif
#ifdef WIN32
#pragma warning(pop)
#endif

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/tryto.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const std::vector<fs::path>& chrome_paths);

QueryData genChromeBasedExtensionContentScripts(
    QueryContext& context, const std::vector<fs::path>& chrome_paths);

/// A helper check to rename bool-type values as 1 or 0.
inline void jsonBoolAsInt(std::string& s) {
  auto expected = tryTo<bool>(s);
  if (expected.isValue()) {
    s = expected.get() ? "1" : "0";
  }
}
} // namespace tables
} // namespace osquery
