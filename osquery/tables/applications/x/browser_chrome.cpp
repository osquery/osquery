/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables/applications/browser_utils.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Each home directory will include custom extensions.
#ifdef __APPLE__
  #define kChromePath "/Library/Application Support/Google/Chrome/Default/"
#else
  #define kChromePath "/.config/google-chrome/Default/"
#endif
#define kChromeExtensionsPath "Extensions/"

QueryData genChromeExtensions(QueryContext& context) {
  return genChromeBasedExtensions(context, (kChromePath kChromeExtensionsPath));
}
}
}
