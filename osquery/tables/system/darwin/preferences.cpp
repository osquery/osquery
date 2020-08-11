/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// The maximum number of subkeys to report for dictionary-type preferences.
const size_t kPreferenceDepthLimit = 20;

struct TRowResults {
 public:
  TRowResults(const Row& r, QueryData& q, size_t d)
      : base(&r), results(&q), depth(d) {}

 public:
  /// The base row, this will be used to produce copies of the row content.
  const Row* const base;

  /// A reference to the mutable results.
  QueryData* const results;

  /// Track the depth as the preferences are recursed.
  size_t depth;
};

/// Walk the supported preference value structures.
void genOSXPrefValues(const CFTypeRef& value,
                      const Row& base,
                      QueryData& results,
                      size_t depth);

void genOSXHashPref(const void* key, const void* value, void* tref) {
  if (key == nullptr || value == nullptr || tref == nullptr) {
    // Paranoia: don't expect the callback application to yield nullptrs.
    return;
  }

  const TRowResults* trow = (const TRowResults*)tref;
  Row r = *(trow->base);
  if (CFGetTypeID((CFTypeRef)key) == CFStringGetTypeID()) {
    if (r["subkey"].size() > 0) {
      r["subkey"] += "/";
    }
    // The subkey is the hash map key.
    r["subkey"] += stringFromCFString((CFStringRef)key);
  }
  genOSXPrefValues(
      static_cast<CFTypeRef>(value), r, *(trow->results), trow->depth);
}

void genOSXListPref(const CFArrayRef& list,
                    const Row& base,
                    QueryData& results,
                    size_t depth) {
  // Iterate over a preference value that contains a list structure.
  for (CFIndex j = 0; j < CFArrayGetCount(list); ++j) {
    Row r = base;
    auto value = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(list, j));
    if (!r["subkey"].empty()) {
      r["subkey"] += '/';
    }
    // The subkey is the index into the list.
    r["subkey"] += std::to_string(j);
    genOSXPrefValues(value, r, results, depth);
  }
}

void genOSXPrefValues(const CFTypeRef& value,
                      const Row& base,
                      QueryData& results,
                      size_t depth) {
  if (value == nullptr) {
    return;
  }

  // Since we recurse when parsing Arrays/Dicts, monitor stack limits.
  if (++depth > kPreferenceDepthLimit) {
    TLOG << "The macOS preference: " << base.at("domain")
         << " exceeded subkey depth limit: " << kPreferenceDepthLimit;
    return;
  }

  // Emit a string representation for each preference type.
  Row r = base;
  if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    r["value"] = stringFromCFNumber(static_cast<CFDataRef>(value));
  } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
    r["value"] = stringFromCFString(static_cast<CFStringRef>(value));
  } else if (CFGetTypeID(value) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime(static_cast<CFDateRef>(value)) +
                     kCFAbsoluteTimeIntervalSince1970;
    r["value"] = std::to_string(std::llround(unix_time));
  } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
    r["value"] = (CFBooleanGetValue(static_cast<CFBooleanRef>(value)) == TRUE)
                     ? "true"
                     : "false";
  } else if (CFGetTypeID(value) == CFDataGetTypeID()) {
    // Do not include data preferences.
  } else if (CFGetTypeID(value) == CFArrayGetTypeID()) {
    genOSXListPref(static_cast<CFArrayRef>(value), base, results, depth);
    return;
  } else if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
    // Generate a row for each hash key.
    TRowResults trow(base, results, depth);
    CFDictionaryApplyFunction(
        static_cast<CFDictionaryRef>(value), &genOSXHashPref, &trow);
    return;
  }

  results.push_back(std::move(r));
}

void genOSXDomainPrefs(const CFStringRef& username,
                       const CFStringRef& domain,
                       bool current_host,
                       QueryData& results) {
  const auto* user = (username != nullptr)
                         ? &username
                         : (isUserAdmin()) ? &kCFPreferencesAnyUser
                                           : &kCFPreferencesCurrentUser;
  const auto* host =
      (current_host) ? &kCFPreferencesCurrentHost : &kCFPreferencesAnyHost;
  auto keys = CFPreferencesCopyKeyList(domain, *user, *host);
  if (keys == nullptr) {
    return;
  }

  auto values = CFPreferencesCopyMultiple(keys, domain, *user, *host);
  if (values == nullptr) {
    CFRelease(keys);
    return;
  }

  std::string username_string;
  if (username != nullptr) {
    username_string = stringFromCFString(username);
  }

  // Iterate over each preference domain's preference name.
  for (CFIndex j = 0; j < CFArrayGetCount(keys); ++j) {
    Row r;

    r["username"] = username_string;
    r["host"] = (current_host) ? "current" : "any";
    r["domain"] = stringFromCFString(domain);
    auto key = static_cast<CFStringRef>(CFArrayGetValueAtIndex(keys, j));
    if (CFStringGetTypeID() != CFGetTypeID(key)) {
      continue;
    }

    // Interesting results/behavior from Microsoft products.
    r["key"] = stringFromCFString(key);
    if (r.at("key").find('>') != std::string::npos ||
        r.at("key").find('<') != std::string::npos || r.at("key").size() == 0) {
      continue;
    }

    // Check if the preference key is managed by a profile.
    auto forced = CFPreferencesAppValueIsForced(key, domain);
    r["forced"] = (forced) ? '1' : '0';

    CFTypeRef value = nullptr;
    if (forced) {
      value = static_cast<CFTypeRef>(CFPreferencesCopyAppValue(key, domain));
    } else {
      // Check the key and key type (which may be any CF type).
      value = static_cast<CFTypeRef>(CFDictionaryGetValue(values, key));
    }
    genOSXPrefValues(value, r, results, 0);
    if (forced) {
      CFRelease(value);
    }
  }

  CFRelease(values);
  CFRelease(keys);
}

QueryData genOSXDefaultPreferences(QueryContext& context) {
  QueryData results;

  CFStringRef username = nullptr;
  if (context.constraints["username"].exists(EQUALS)) {
    auto users = context.constraints["username"].getAll(EQUALS);
    username = CFStringCreateWithCString(
        kCFAllocatorDefault, (*users.begin()).c_str(), kCFStringEncodingUTF8);
  }

  const auto* user = (username != nullptr)
                         ? &username
                         : (isUserAdmin()) ? &kCFPreferencesAnyUser
                                           : &kCFPreferencesCurrentUser;

  // Need lambda to iterate the map.
  auto preferencesIterator =
      ([&results, &username](CFMutableArrayRef& am, bool current_host) {
        for (CFIndex i = 0; i < CFArrayGetCount(am); ++i) {
          auto domain = static_cast<CFStringRef>(CFArrayGetValueAtIndex(am, i));
          genOSXDomainPrefs(username, domain, current_host, results);
        }
      });

  CFMutableArrayRef app_map = nullptr;
  if (context.constraints["domain"].exists(EQUALS)) {
    // If a specific domain is requested, speed up the set of type conversions.
    auto domains = context.constraints["domain"].getAll(EQUALS);
    app_map = CFArrayCreateMutable(
        kCFAllocatorDefault, domains.size(), &kCFTypeArrayCallBacks);
    for (const auto& domain : domains) {
      auto cf_domain = CFStringCreateWithCString(
          kCFAllocatorDefault, domain.c_str(), kCFStringEncodingASCII);
      CFArrayAppendValue(app_map, cf_domain);
      CFRelease(cf_domain);
    }

    // Iterate over each preference domain (applicationID).
    preferencesIterator(app_map, true);
    preferencesIterator(app_map, false);
    CFRelease(app_map);
  } else {
    // Listing ALL application preferences is deprecated.
    OSQUERY_USE_DEPRECATED(
        app_map = (CFMutableArrayRef)CFPreferencesCopyApplicationList(
            *user, kCFPreferencesCurrentHost));
    if (app_map != nullptr) {
      // Iterate over each preference domain (applicationID).
      preferencesIterator(app_map, true);
      CFRelease(app_map);
    }

    // Again for 'any' host.
    OSQUERY_USE_DEPRECATED(
        app_map = (CFMutableArrayRef)CFPreferencesCopyApplicationList(
            *user, kCFPreferencesAnyHost));
    if (app_map != nullptr) {
      // Iterate over each preference domain (applicationID).
      preferencesIterator(app_map, false);
      CFRelease(app_map);
    }
  }

  if (username != nullptr) {
    CFRelease(username);
  }

  return results;
}

void genOSXPlistPrefValue(const pt::ptree& tree,
                          const Row& base,
                          unsigned int level,
                          QueryData& results) {
  if (tree.empty()) {
    Row r = base;
    r["value"] = tree.data();
    results.push_back(std::move(r));
    // No more levels to parse.
    return;
  }

  for (const auto& item : tree) {
    Row r = base;
    if (r["subkey"].size() > 0) {
      r["subkey"] += '/';
      if (item.first.size() == 0) {
        r["subkey"] += std::to_string(level++);
      }
    }

    r["subkey"] += item.first;
    genOSXPlistPrefValue(item.second, r, level, results);
  }
}

QueryData genOSXPlist(QueryContext& context) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  for (const auto& path : paths) {
    if (!pathExists(path).ok() || !isReadable(path).ok()) {
      VLOG(1) << "Cannot find/read defaults plist from path: " + path;
      continue;
    }

    pt::ptree tree;
    if (!osquery::parsePlist(path, tree).ok()) {
      VLOG(1) << "Could not parse plist: " + path;
      continue;
    }

    for (const auto& item : tree) {
      Row r;

      r["path"] = path;
      r["key"] = item.first;
      r["subkey"] = "";
      genOSXPlistPrefValue(item.second, r, 0, results);
    }
  }

  return results;
}
}
}
