/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/utils/scope_guard.h"
#import <Foundation/Foundation.h>
#include <dlfcn.h>

#include <vector>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// Types and dispositions from
// https://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html

// Disposition flags for Background Task Management items
enum class DispositionFlag : uint32_t {
  Enabled = 0x01,
  Allowed = 0x02,
  Hidden = 0x04,
  Notified = 0x08,
};

// Type flags for Background Task Management items
enum class TypeFlag : uint32_t {
  UserItem = 0x00001,
  App = 0x00002,
  LoginItem = 0x00004,
  Agent = 0x00008,
  Daemon = 0x00010,
  Developer = 0x00020,
  Spotlight = 0x00040,
  Quicklook = 0x00800,
  Curated = 0x80000,
  Legacy = 0x10000,
};

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
};

// Helper function to convert disposition flags to string
std::string dispositionToString(uint32_t disposition) {
  std::vector<std::string> flags;
  if (disposition & (uint32_t)DispositionFlag::Enabled) {
    flags.push_back("enabled");
  }
  if (disposition & (uint32_t)DispositionFlag::Allowed) {
    flags.push_back("allowed");
  }
  if (disposition & (uint32_t)DispositionFlag::Hidden) {
    flags.push_back("hidden");
  }
  if (disposition & (uint32_t)DispositionFlag::Notified) {
    flags.push_back("notified");
  }
  if (flags.empty()) {
    return "unknown";
  }
  return osquery::join(flags, ", ");
}

// Helper function to convert type flags to string
std::string typeToString(uint32_t type) {
  std::vector<std::string> flags;
  if (type & (uint32_t)TypeFlag::UserItem) {
    flags.push_back("user item");
  }
  if (type & (uint32_t)TypeFlag::App) {
    flags.push_back("app");
  }
  if (type & (uint32_t)TypeFlag::LoginItem) {
    flags.push_back("login item");
  }
  if (type & (uint32_t)TypeFlag::Agent) {
    flags.push_back("agent");
  }
  if (type & (uint32_t)TypeFlag::Daemon) {
    flags.push_back("daemon");
  }
  if (type & (uint32_t)TypeFlag::Developer) {
    flags.push_back("developer");
  }
  if (type & (uint32_t)TypeFlag::Spotlight) {
    flags.push_back("spotlight");
  }
  if (type & (uint32_t)TypeFlag::Quicklook) {
    flags.push_back("quicklook");
  }
  if (type & (uint32_t)TypeFlag::Curated) {
    flags.push_back("curated");
  }
  if (type & (uint32_t)TypeFlag::Legacy) {
    flags.push_back("legacy");
  }
  if (flags.empty()) {
    return "unknown";
  }
  return osquery::join(flags, ", ");
}

void genLibraryStartupItems(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      if (!fs::exists(it->status()) || !fs::is_directory(it->status())) {
        continue;
      }

      Row r;
      r["name"] = it->path().string();
      r["path"] = it->path().string();
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      r["source"] = sysdir;
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

void parseItem(const std::string& uuid, id item, QueryData& results) {
  if (item == nil) {
    return;
  }

  Row r;

  // Convert type property (bitmask) to string
  r["type"] = "unknown";
  if ([item respondsToSelector:@selector(type)]) {
    id typeProperty = [item valueForKey:@"type"];
    if (typeProperty != nil &&
        [typeProperty respondsToSelector:@selector(unsignedIntValue)]) {
      uint32_t typeValue = [typeProperty unsignedIntValue];

      // Skip developer items and quicklook items because they don't seem to be
      // startup items
      if (typeValue & (uint32_t)TypeFlag::Developer ||
          typeValue & (uint32_t)TypeFlag::Quicklook ||
          typeValue & (uint32_t)TypeFlag::Spotlight) {
        return;
      }
      r["type"] = typeToString(typeValue);
    }
  }

  if ([item respondsToSelector:@selector(name)]) {
    id nameProperty = [item valueForKey:@"name"];
    if (nameProperty != nil) {
      r["name"] = std::string([[nameProperty description] UTF8String]);
    }
  }

  // Convert disposition property (bitmask) to string
  r["status"] = "unknown";
  if ([item respondsToSelector:@selector(disposition)]) {
    id dispositionProperty = [item valueForKey:@"disposition"];
    if (dispositionProperty != nil &&
        [dispositionProperty respondsToSelector:@selector(unsignedIntValue)]) {
      uint32_t dispositionValue = [dispositionProperty unsignedIntValue];
      r["status"] = dispositionToString(dispositionValue);
    }
  }

  if ([item respondsToSelector:@selector(url)]) {
    id urlProperty = [item valueForKey:@"url"];
    if (urlProperty != nil && [urlProperty isKindOfClass:[NSURL class]]) {
      NSURL* url = (NSURL*)urlProperty;
      NSString* path = [url path];
      if (path != nil) {
        r["path"] = std::string([path UTF8String]);
      }
    }
  }

  if ([item respondsToSelector:@selector(programArguments)]) {
    id programArgumentsProperty = [item valueForKey:@"programArguments"];
    if (programArgumentsProperty != nil &&
        [programArgumentsProperty isKindOfClass:[NSArray class]]) {
      NSArray* programArguments = (NSArray*)programArgumentsProperty;
      std::vector<std::string> args;
      for (id arg in programArguments) {
        if ([arg isKindOfClass:[NSString class]]) {
          NSString* argString = (NSString*)arg;
          args.push_back(std::string([argString UTF8String]));
        }
      }
      if (!args.empty()) {
        r["args"] = osquery::join(args, " ");
      }
    }
  }

  r["username"] = uuid;
  r["source"] = "Background Task Management";
  results.push_back(r);
}

void parseItemsByUser(id uuid, id items, QueryData& results) {
  if (items == nil) {
    return;
  }

  std::string uuidString = std::string([[uuid description] UTF8String]);

  // Top level should always be an array
  if (![items isKindOfClass:[NSArray class]]) {
    VLOG(1) << "parseItemsByUser: expected array but got "
            << [[items description] UTF8String];
    return;
  }

  for (id item in (NSArray*)items) {
    parseItem(uuidString, item, results);
  }
}

void genBtmStartupItems(QueryData& results) {
  // Find the most recently modified .btm file using SQL query. It's not clear
  // when macOS decides to increment this number, or how the file format may
  // change. Future readers may need to make updates. Efforts were made to check
  // all the calls so that we don't get crashes if the format changes.
  std::string query =
      "SELECT path FROM file WHERE directory = '"
      "/private/var/db/com.apple.backgroundtaskmanagement/"
      "' AND filename LIKE '%.btm' ORDER BY mtime DESC LIMIT 1";
  SQL sql(query);
  if (!sql.ok() || sql.rows().empty()) {
    LOG(ERROR) << "Found no .btm database in "
                  "/private/var/db/com.apple.backgroundtaskmanagement/";
    return;
  }

  std::string most_recent_btm_file = sql.rows()[0].at("path");

  // Read the BTM file content
  std::string btm_content;
  auto read_status = readFile(most_recent_btm_file, btm_content);
  if (!read_status.ok()) {
    VLOG(1) << "Failed to read BTM file: " << most_recent_btm_file;
    return;
  }

  @autoreleasepool {
    // Load the BTM daemon to make the Storage class available via
    // NSClassFromString
    void* btmd = dlopen(
        "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/"
        "Resources/backgroundtaskmanagementd",
        RTLD_LAZY);
    if (btmd == NULL) {
      LOG(ERROR) << "Failed to load BTM daemon: " << dlerror();
      return;
    }
    const auto btmd_guard = scope_guard::create([&]() { dlclose(btmd); });

    Class StorageClass = NSClassFromString(@"Storage");
    if (StorageClass == nil) {
      LOG(ERROR) << "Storage class not found in BTM daemon";
      return;
    }

    // Convert the file content to NSData
    NSData* btm_data = [NSData dataWithBytes:btm_content.data()
                                      length:btm_content.size()];
    if (btm_data == nil) {
      LOG(ERROR) << "Failed to create NSData from BTM file content";
      return;
    }

    // Create an unarchiver for the BTM data
    NSError* error = nil;
    NSKeyedUnarchiver* unarchiver =
        [[NSKeyedUnarchiver alloc] initForReadingFromData:btm_data
                                                    error:&error];
    if (unarchiver == nil) {
      VLOG(1) << "Failed to create NSKeyedUnarchiver: "
              << [error.localizedDescription UTF8String];
      return;
    }

    // Decode the Storage object. The key "store" is where the Storage object
    // is stored in the BTM file
    id store = nil;
    @try {
      // Use try/catch here because we don't control the implementation of the
      // decoders and can't be sure that they will not raise exceptions on
      // failure.
      unarchiver.decodingFailurePolicy = NSDecodingFailurePolicyRaiseException;
      store = [unarchiver decodeObjectOfClass:StorageClass forKey:@"store"];
      [unarchiver finishDecoding];
    } @catch (NSException* exception) {
      VLOG(1) << "Failed to decode store object from BTM file "
              << most_recent_btm_file << ": "
              << [exception.description UTF8String];
      return;
    }

    if (store == nil) {
      LOG(ERROR) << "decode did not return error but store is nil";
      return;
    }

    if (![store isKindOfClass:StorageClass]) {
      LOG(ERROR) << "store is not a Storage object";
      return;
    }

    id itemsByUser = [store valueForKey:@"itemsByUserIdentifier"];
    if (itemsByUser == nil ||
        ![itemsByUser isKindOfClass:[NSDictionary class]]) {
      LOG(ERROR) << "itemsByUser is not a dictionary";
      return;
    }
    for (id uuid in itemsByUser) {
      id items = itemsByUser[uuid];
      parseItemsByUser(uuid, items, results);
    }
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // Find system wide startup items in Library directories.
  for (const auto& dir : kLibraryStartupItemPaths) {
    genLibraryStartupItems(dir, results);
  }

  // Find startup items from Background Task Management (.btm files)
  genBtmStartupItems(results);

  return results;
}
} // namespace tables
} // namespace osquery
