/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tables/applications/browser_utils.h>
#include <osquery/utils/info/platform_type.h>

using namespace std;

namespace fs = boost::filesystem;

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

  fs::path bravePath;

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    bravePath = "\\AppData\\Roaming\\brave\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    bravePath = "/Library/Application Support/BraveSoftware/Brave-Browser/%/Extensions/";
  } else {
    bravePath = "/.config/BraveSoftware/Brave-Browser/%/Extensions/";
  }

  fs::path chromiumPath;

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    chromiumPath = "\\AppData\\Local\\Chromium\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    chromiumPath = "/Library/Application Support/Chromium/%/Extensions/";
  } else {
    chromiumPath = "/.config/chromium/%/Extensions/";
  }

  std::vector<fs::path> chromePaths{chromePath, bravePath, chromiumPath};

  return genChromeBasedExtensions(context, chromePaths);
}

}
}
