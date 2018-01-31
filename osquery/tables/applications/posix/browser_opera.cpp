/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/tables/applications/browser_utils.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_opera_extensions_defs.hpp>

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#ifdef __APPLE__
#define kOperaPath "/Library/Application Support/com.operasoftware.Opera/"
#else
#define kOperaPath "/.config/opera/"
#endif
#define kOperaExtensionsPath "Extensions/"

QueryData genOperaExtensions(QueryContext& context) {
  return genChromeBasedExtensions(context, (kOperaPath kOperaExtensionsPath));
}
}
}
