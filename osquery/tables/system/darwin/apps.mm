/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <Foundation/Foundation.h>

#include <CoreServices/CoreServices.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::map<std::string, std::string> kAppsInfoPlistTopLevelStringKeys = {
    {"CFBundleExecutable", "bundle_executable"},
    {"CFBundleIdentifier", "bundle_identifier"},
    {"CFBundleName", "bundle_name"},
    {"CFBundleShortVersionString", "bundle_short_version"},
    {"CFBundleVersion", "bundle_version"},
    {"CFBundlePackageType", "bundle_package_type"},
    {"LSEnvironment", "environment"},
    {"LSUIElement", "element"},
    {"CFBundleDevelopmentRegion", "development_region"},
    {"CFBundleDisplayName", "display_name"},
    {"CFBundleGetInfoString", "info_string"},
    {"DTCompiler", "compiler"},
    {"LSMinimumSystemVersion", "minimum_system_version"},
    {"LSApplicationCategoryType", "category"},
    {"NSAppleScriptEnabled", "applescript_enabled"},
    {"NSHumanReadableCopyright", "copyright"},
};

const std::vector<std::string> kHomeDirSearchPaths = {
    "Applications", "Desktop", "Downloads",
};

const std::vector<std::string> kSystemSearchPaths = {
    "/Applications",
    "/System/Library/Core Services/Applications",
    "/Library/Apple/System/Library/CoreServices",
    "/Users/Shared/Applications",
};

enum AppSchemeFlags {
  kSchemeNormal = 0,
  // Default flag from the list of schemes on a default OS X 10.10 install.
  kSchemeSystemDefault = 1,
  // Protected flag from Apple Reference: Inter-app Communication
  kSchemeProtected = 2,
};

const std::map<std::string, unsigned short> kApplicationSchemes = {
    {"account", 0},
    {"addressbook", kSchemeSystemDefault},
    {"afp", kSchemeSystemDefault | kSchemeProtected},
    {"aim", kSchemeSystemDefault},
    {"alfred", 0},
    {"alfredapp", 0},
    {"app-prefs", 0},
    {"applefeedback", kSchemeSystemDefault},
    {"applescript", kSchemeSystemDefault},
    {"apupdate", kSchemeSystemDefault},
    {"at", kSchemeSystemDefault | kSchemeProtected},
    {"atom", 0},
    {"bluejeans", 0},
    {"calinvite", 0},
    {"calinvitelist", 0},
    {"callto", 0},
    {"calshow", 0},
    {"cloudphoto", kSchemeSystemDefault},
    {"conf", 0},
    {"daap", kSchemeSystemDefault},
    {"dict", kSchemeSystemDefault},
    {"facetime", kSchemeSystemDefault | kSchemeProtected},
    {"fb", kSchemeSystemDefault},
    {"fbauth", 0},
    {"file", kSchemeSystemDefault | kSchemeProtected},
    {"ftp", kSchemeSystemDefault | kSchemeProtected},
    {"gamecenter", kSchemeSystemDefault},
    {"gopher", 0},
    {"grammar", 0},
    {"h323", 0},
    {"help", kSchemeSystemDefault},
    {"http", kSchemeSystemDefault | kSchemeProtected},
    {"https", kSchemeSystemDefault | kSchemeProtected},
    {"iadoptout", 0},
    {"ibooks", kSchemeSystemDefault},
    {"ical", kSchemeSystemDefault},
    {"ichat", kSchemeSystemDefault},
    {"icloud-sharing", kSchemeSystemDefault},
    {"im", kSchemeSystemDefault},
    {"imessage", kSchemeSystemDefault},
    {"ipps", kSchemeSystemDefault},
    {"irc", 0},
    {"itls", kSchemeSystemDefault},
    {"itms", kSchemeSystemDefault},
    {"itms-books", kSchemeSystemDefault},
    {"itms-bookss", kSchemeSystemDefault},
    {"itmsp-app", 0},
    {"itunesradio", kSchemeSystemDefault},
    {"macappstore", kSchemeSystemDefault},
    {"macappstores", kSchemeSystemDefault},
    {"mailto", kSchemeSystemDefault | kSchemeProtected},
    {"map", 0},
    {"maps", kSchemeSystemDefault},
    {"message", kSchemeSystemDefault},
    {"messages", kSchemeSystemDefault},
    {"ms-excel", 0},
    {"ms-word", 0},
    {"munki", 0},
    {"news", kSchemeSystemDefault | kSchemeProtected},
    {"nntp", 0},
    {"nwnode", kSchemeSystemDefault | kSchemeProtected},
    {"omnifocus", 0},
    {"ophttp", 0},
    {"pcast", kSchemeSystemDefault},
    {"photos", kSchemeSystemDefault},
    {"photos-event", 0},
    {"photos-migrate-iphoto", 0},
    {"photos-redirect", 0},
    {"powerpoint", 0},
    {"prefs", 0},
    {"qs", 0},
    {"qsinstall", 0},
    {"qss-http", 0},
    {"qssp-http", 0},
    {"reminders", kSchemeSystemDefault},
    {"rtsp", kSchemeSystemDefault},
    {"shoebox", 0},
    {"slack", 0},
    {"smb", kSchemeSystemDefault | kSchemeProtected},
    {"sms", kSchemeSystemDefault | kSchemeProtected},
    {"ssh", kSchemeSystemDefault},
    {"tel", kSchemeSystemDefault | kSchemeProtected},
    {"telnet", kSchemeSystemDefault},
    {"twitter", kSchemeSystemDefault},
    {"txmt", 0},
    {"vnc", kSchemeSystemDefault | kSchemeProtected},
    {"wais", 0},
    {"webapp", 0},
    {"webcal", kSchemeSystemDefault},
    {"whois", 0},
    {"wunderlist", 0},
    {"xmpp", kSchemeSystemDefault},
    {"yelp", 0},
};

void genApplicationsFromPath(const fs::path& path,
                             std::set<std::string>& apps) {
  std::vector<std::string> new_apps;
  if (!osquery::listDirectoriesInDirectory(path.string(), new_apps).ok()) {
    return;
  }

  for (const auto& app : new_apps) {
    if (pathExists(app + "/Contents/Info.plist")) {
      apps.insert(app + "/Contents/Info.plist");
    }
  }
}

void genApplication(const pt::ptree& tree,
                    const fs::path& path,
                    QueryData& results) {
  Row r;
  r["name"] = path.parent_path().parent_path().filename().string();
  r["path"] = path.parent_path().parent_path().string();

  NSString* filePath =
      [NSString stringWithUTF8String:path.parent_path().parent_path().c_str()];
  MDItemRef mdItem = MDItemCreate(NULL, (CFStringRef)filePath);

  if (mdItem != nullptr) {
    NSDate* lastOpened = static_cast<NSDate*>(
        CFBridgingRelease(MDItemCopyAttribute(mdItem, kMDItemLastUsedDate)));
    if (lastOpened != nullptr) {
      r["last_opened_time"] = INTEGER([lastOpened timeIntervalSince1970]);
    } else {
      r["last_opened_time"] = INTEGER(-1);
    }
    CFRelease(mdItem);
    mdItem = NULL;
  } else {
    r["last_opened_time"] = INTEGER(-1);
  }

  // Loop through each column and its mapped Info.plist key name.
  for (const auto& item : kAppsInfoPlistTopLevelStringKeys) {
    r[item.second] = tree.get<std::string>(item.first, "");
    // Change boolean values into integer 1, 0.
    if (r[item.second] == "true" || r[item.second] == "YES" ||
        r[item.second] == "Yes") {
      r[item.second] = INTEGER(1);
    } else if (r[item.second] == "false" || r[item.second] == "NO" ||
               r[item.second] == "No") {
      r[item.second] = INTEGER(0);
    }
  }
  results.push_back(std::move(r));
}

Status genAppsFromLaunchServices(std::set<std::string>& apps) {
  // Resolve the protected/private symbol safely.
  CFBundleRef ls_bundle =
      CFBundleGetBundleWithIdentifier(CFSTR("com.apple.LaunchServices"));
  if (ls_bundle == nullptr) {
    return Status(1, "LaunchServices list missing");
  }

  auto LSCopyAllApplicationURLs =
      (OSStatus(*)(CFArrayRef*))CFBundleGetFunctionPointerForName(
          ls_bundle, CFSTR("_LSCopyAllApplicationURLs"));
  // If the symbol did not exist we will not have a handle.
  if (LSCopyAllApplicationURLs == nullptr) {
    return Status(1, "LaunchServices list missing");
  }

  CFArrayRef ls_apps = nullptr;
  if (LSCopyAllApplicationURLs(&ls_apps) != noErr || ls_apps == nullptr) {
    return Status(1, "Could not list LaunchServices applications");
  }

  for (id app in (__bridge NSArray*)ls_apps) {
    if (app != nil && [app isKindOfClass:[NSURL class]]) {
      apps.insert(std::string([[app path] UTF8String]) +
                  "/Contents/Info.plist");
    }
  }

  CFRelease(ls_apps);
  return Status(0, "OK");
}

QueryData genApps(QueryContext& context) {
  QueryData results;

  // Application path accumulator.
  std::set<std::string> apps;
  @autoreleasepool {
    // Try to use the OS X LaunchServices API.
    if (!genAppsFromLaunchServices(apps).ok()) {
      // Otherwise, the LaunchServices API failed, 'manually' search for apps.
      // Walk through several groups of common search paths that may contain
      // apps.
      if (context.constraints["path"].exists(EQUALS)) {
        auto app_constraints = context.constraints["path"].getAll(EQUALS);
        for (const auto& app : app_constraints) {
          apps.insert(app + "/Contents/Info.plist");
        }
      } else {
        for (const auto& path : kSystemSearchPaths) {
          genApplicationsFromPath(path, apps);
        }

        // List all users on the system, and walk common search paths with
        // homes.
        auto homes = osquery::getHomeDirectories();
        for (const auto& home : homes) {
          for (const auto& path : kHomeDirSearchPaths) {
            genApplicationsFromPath(home / path, apps);
          }
        }
      }
    }

    // The osquery::parsePlist method will reset/clear a property tree.
    // Keeping the data structure in a larger scope preserves allocations
    // between similar-sized trees.
    pt::ptree tree;

    // For each found application (path with an Info.plist) parse the plist.
    for (const auto& path : apps) {
      if (!osquery::pathExists(path)) {
        continue;
      }

      if (!osquery::parsePlist(path, tree).ok()) {
        TLOG << "Error parsing application plist: " << path;
        continue;
      }

      // Using the parsed plist, pull out each interesting key.
      genApplication(tree, path, results);
    }
  }
  return results;
}

QueryData genAppSchemes(QueryContext& context) {
  QueryData results;

  @autoreleasepool {
    for (const auto& scheme : kApplicationSchemes) {
      auto protocol = scheme.first + "://";
      auto cfprotocol = CFStringCreateWithCString(
          kCFAllocatorDefault, protocol.c_str(), protocol.length());
      if (cfprotocol == nullptr) {
        continue;
      }

      // Create a "fake" URL that only contains the protocol component of a URI.
      auto url =
          CFURLCreateWithString(kCFAllocatorDefault, cfprotocol, nullptr);
      CFRelease(cfprotocol);
      if (url == nullptr) {
        continue;
      }

      // List all application bundles that request this protocol scheme.
      auto apps = LSCopyApplicationURLsForURL(url, kLSRolesAll);
      if (apps == nullptr) {
        CFRelease(url);
        continue;
      }

      // Check the default handler assigned to the protocol scheme.
      // This only applies to 10.10, so resolve the symbol at runtime.
      CFBundleRef ls_bundle =
          CFBundleGetBundleWithIdentifier(CFSTR("com.apple.LaunchServices"));
      CFURLRef default_app = nullptr;
      if (ls_bundle != nullptr) {
        auto _LSCopyDefaultApplicationURLForURL =
            (CFURLRef(*)(CFURLRef, LSRolesMask, CFErrorRef*))
                CFBundleGetFunctionPointerForName(
                    ls_bundle, CFSTR("LSCopyDefaultApplicationURLForURL"));
        // If the symbol did not exist we will not have a handle.
        if (_LSCopyDefaultApplicationURLForURL != nullptr) {
          default_app =
              _LSCopyDefaultApplicationURLForURL(url, kLSRolesAll, nullptr);
        }
      }

      CFRelease(url);
      for (CFIndex i = 0; i < CFArrayGetCount(apps); i++) {
        Row r;
        r["scheme"] = scheme.first;

        auto app = CFArrayGetValueAtIndex(apps, i);
        if (app == nullptr || CFGetTypeID(app) != CFURLGetTypeID()) {
          // Handle problems with application listings.
          continue;
        }

        auto path =
            CFURLCopyFileSystemPath((CFURLRef)app, kCFURLPOSIXPathStyle);
        if (path == nullptr) {
          continue;
        }

        r["handler"] = stringFromCFString(path);
        CFRelease(path);
        // Check if the handler is set (in the OS) as the default.
        if (default_app != nullptr &&
            CFEqual((CFTypeRef)app, (CFTypeRef)default_app)) {
          r["enabled"] = "1";
        } else {
          r["enabled"] = "0";
        }

        r["external"] = (scheme.second & kSchemeSystemDefault) ? "0" : "1";
        r["protected"] = (scheme.second & kSchemeProtected) ? "1" : "0";
        results.push_back(r);
      }

      if (default_app != nullptr) {
        CFRelease(default_app);
      }
      CFRelease(apps);
    }
  }
  return results;
}
}
}
