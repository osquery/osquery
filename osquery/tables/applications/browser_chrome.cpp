/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tables/applications/browser_utils.h>
#include <osquery/utils/info/platform_type.h>

namespace fs = boost::filesystem;

namespace {
fs::path chrome_path;
fs::path chromium_path;
fs::path brave_path;
} // namespace

namespace osquery {
namespace tables {

#ifdef WIN32
#pragma warning(disable : 4503)
#endif

QueryData genChromeExtensions(QueryContext& context) {

  /// Each home directory will include custom extensions.
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    chrome_path =
        "\\AppData\\Local\\Google\\Chrome\\User Data\\%\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    chrome_path = "/Library/Application Support/Google/Chrome/%/Extensions/";
  } else {
    chrome_path = "/.config/google-chrome/%/Extensions/";
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    brave_path = "\\AppData\\Roaming\\brave\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    brave_path =
        "/Library/Application "
        "Support/BraveSoftware/Brave-Browser/%/Extensions/";
  } else {
    brave_path = "/.config/BraveSoftware/Brave-Browser/%/Extensions/";
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    chromium_path = "\\AppData\\Local\\Chromium\\Extensions\\";
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    chromium_path = "/Library/Application Support/Chromium/%/Extensions/";
  } else {
    chromium_path = "/.config/chromium/%/Extensions/";
  }

  std::vector<fs::path> chrome_paths{chrome_path, brave_path, chromium_path};

  return genChromeBasedExtensions(context, chrome_paths);
}
}
}
