/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tables/applications/browser_utils.h>

namespace fs = boost::filesystem;

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
