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

#ifdef WIN32
#pragma warning(disable : 4503)
#endif

QueryData genChromeExtensions(QueryContext& context) {
  fs::path chromePath;

  /// Each home directory will include custom extensions.
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    chromePath = "\\AppData\\Local\\Google\\Chrome\\User Data\\%\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    chromePath = "/Library/Application Support/Google/Chrome/%/Extensions/";
  } else {
    chromePath = "/.config/google-chrome/%/Extensions/";
  }

  return genChromeBasedExtensions(context, chromePath);
}
}
}
