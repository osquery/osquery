/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/applications/browser_utils.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

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
