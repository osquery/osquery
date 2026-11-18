/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <Foundation/Foundation.h>
#include <dlfcn.h>

#include <map>
#include <regex>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/startup_items.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/darwin/plist.h>
#include <osquery/utils/scope_guard.h>

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

const std::string kBtmDirectory =
    "/private/var/db/com.apple.backgroundtaskmanagement/";

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

void parseItem(const std::string& username, id item, QueryData& results) {
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

  r["username"] = username;
  r["source"] = "Background Task Management";
  results.push_back(r);
}

void parseItemsByUser(const std::string& username,
                      id items,
                      QueryData& results) {
  if (items == nil) {
    return;
  }

  // Top level should always be an array
  if (![items isKindOfClass:[NSArray class]]) {
    VLOG(1) << "parseItemsByUser: expected array but got "
            << [[items description] UTF8String];
    return;
  }

  for (id item in (NSArray*)items) {
    parseItem(username, item, results);
  }
}

void parseUserStore(const std::string& username,
                    id userStore,
                    QueryData& results) {
  if (userStore == nil || ![userStore respondsToSelector:@selector(records)]) {
    return;
  }

  parseItemsByUser(username, [userStore valueForKey:@"records"], results);
}

BtmDatabaseFiles selectBtmDatabaseFiles(
    const std::vector<std::string>& filenames) {
  // It's not clear when macOS decides to increment the version, or how the
  // file format may change. Version 18 (macOS 27) split each user's items out
  // of the global archive into their own file. Future readers may need to make
  // updates.
  static const std::regex kBtmFilename(
      "^BackgroundItems-v([0-9]+)(?:-(.+))?\\.btm$");

  int latest_version = -1;
  BtmDatabaseFiles latest;
  for (const auto& filename : filenames) {
    std::smatch match;
    if (!std::regex_match(filename, match, kBtmFilename)) {
      continue;
    }

    auto version = tryTo<int>(match[1].str());
    if (version.isError() || version.get() < latest_version) {
      continue;
    }

    if (version.get() > latest_version) {
      latest_version = version.get();
      latest = BtmDatabaseFiles{};
    }

    if (match[2].matched) {
      latest.user_store_files.push_back({filename, match[2].str()});
    } else {
      latest.global_filename = filename;
    }
  }

  return latest;
}

BtmDatabaseFiles findBtmDatabaseFiles() {
  fs::path btm_dir_path(kBtmDirectory);
  if (!fs::exists(btm_dir_path) || !fs::is_directory(btm_dir_path)) {
    LOG(ERROR) << "BTM directory does not exist or is not a directory: "
               << kBtmDirectory;
    return {};
  }

  std::vector<std::string> filenames;
  try {
    fs::directory_iterator it(btm_dir_path), end;
    for (; it != end; ++it) {
      if (fs::is_regular_file(it->status())) {
        filenames.push_back(it->path().filename().string());
      }
    }
  } catch (const fs::filesystem_error& e) {
    LOG(ERROR) << "Error traversing BTM directory: " << e.what();
    return {};
  }

  auto files = selectBtmDatabaseFiles(filenames);
  if (files.global_filename.empty() && files.user_store_files.empty()) {
    LOG(ERROR) << "Found no .btm database in " << kBtmDirectory;
  }

  return files;
}

// Efforts were made to check all the calls so that we don't get crashes if the
// format changes. Returns nil if the archive has no `cls` object at `key`.
id decodeBtmArchive(const std::string& path, Class cls, NSString* key) {
  std::string content;
  auto read_status = readFile(path, content);
  if (!read_status.ok()) {
    VLOG(1) << "Failed to read BTM file: " << path;
    return nil;
  }

  NSData* data = [NSData dataWithBytes:content.data() length:content.size()];
  if (data == nil) {
    LOG(ERROR) << "Failed to create NSData from BTM file content";
    return nil;
  }

  NSError* error = nil;
  NSKeyedUnarchiver* unarchiver =
      [[NSKeyedUnarchiver alloc] initForReadingFromData:data error:&error];
  if (unarchiver == nil) {
    VLOG(1) << "Failed to create NSKeyedUnarchiver: "
            << [error.localizedDescription UTF8String];
    return nil;
  }

  id object = nil;
  @try {
    // Use try/catch here because we don't control the implementation of the
    // decoders and can't be sure that they will not raise exceptions on
    // failure.
    unarchiver.decodingFailurePolicy = NSDecodingFailurePolicyRaiseException;
    object = [unarchiver decodeObjectOfClass:cls forKey:key];
    [unarchiver finishDecoding];
  } @catch (NSException* exception) {
    VLOG(1) << "Failed to decode " << [key UTF8String] << " from BTM file "
            << path << ": " << [exception.description UTF8String];
    return nil;
  }

  if (object != nil && ![object isKindOfClass:cls]) {
    LOG(ERROR) << [key UTF8String] << " in BTM file " << path << " is not a "
               << [NSStringFromClass(cls) UTF8String] << " object";
    return nil;
  }

  return object;
}

std::map<std::string, std::string> getUsernamesByUuid() {
  std::map<std::string, std::string> usernames;
  QueryData users = SQL::selectAllFrom("users");
  for (const auto& user_row : users) {
    if (user_row.count("uuid") > 0 && user_row.count("username") > 0) {
      usernames[user_row.at("uuid")] = user_row.at("username");
    }
  }
  return usernames;
}

void genBtmStartupItems(QueryData& results) {
  auto files = findBtmDatabaseFiles();
  if (files.global_filename.empty() && files.user_store_files.empty()) {
    return;
  }

  @autoreleasepool {
    // Load the BTM daemon to make the Storage and BTMUserStore classes
    // available via NSClassFromString
    void* btmd = dlopen(
        "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/"
        "Resources/backgroundtaskmanagementd",
        RTLD_LAZY);
    if (btmd == NULL) {
      LOG(ERROR) << "Failed to load BTM daemon: " << dlerror();
      return;
    }
    const auto btmd_guard = scope_guard::create([&]() { dlclose(btmd); });

    // Look up username from UUID, fallback to UUID if not found
    const auto uuidToUsername = getUsernamesByUuid();
    auto usernameFor = [&uuidToUsername](const std::string& uuid) {
      auto it = uuidToUsername.find(uuid);
      return it != uuidToUsername.end() ? it->second : uuid;
    };

    // Since version 18 the global archive no longer holds any items, so only
    // the per-user archives are read.
    if (!files.user_store_files.empty()) {
      Class UserStoreClass = NSClassFromString(@"BTMUserStore");
      if (UserStoreClass == nil) {
        LOG(ERROR) << "BTMUserStore class not found in BTM daemon";
        return;
      }

      for (const auto& file : files.user_store_files) {
        id userStore = decodeBtmArchive(
            kBtmDirectory + file.filename, UserStoreClass, @"userStore");
        if (userStore == nil) {
          LOG(ERROR) << "Failed to decode userStore from BTM file "
                     << file.filename;
          continue;
        }

        parseUserStore(usernameFor(file.user_identifier), userStore, results);
      }
      return;
    }

    Class StorageClass = NSClassFromString(@"Storage");
    if (StorageClass == nil) {
      LOG(ERROR) << "Storage class not found in BTM daemon";
      return;
    }

    id store = decodeBtmArchive(
        kBtmDirectory + files.global_filename, StorageClass, @"store");
    if (store == nil) {
      LOG(ERROR) << "Failed to decode store from BTM file "
                 << files.global_filename;
      return;
    }

    id itemsByUser = [store valueForKey:@"itemsByUserIdentifier"];
    if (itemsByUser == nil ||
        ![itemsByUser isKindOfClass:[NSDictionary class]]) {
      LOG(ERROR) << "itemsByUser is not a dictionary";
      return;
    }

    for (id uuid in itemsByUser) {
      parseItemsByUser(usernameFor([[uuid description] UTF8String]),
                       itemsByUser[uuid],
                       results);
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
