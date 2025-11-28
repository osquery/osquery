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
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;

// Path to the BTM daemon that contains the Storage class
#define BTM_DAEMON                                                             \
  "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/"      \
  "Resources/backgroundtaskmanagementd"

// Global handle to the loaded daemon
static void* btmd = NULL;

// Types and dispositions from
// https://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html

// Disposition values for Background Task Management items
const std::map<uint32_t, std::string> kDispositionValues = {
    {0x01, "Enabled"},
    {0x02, "Allowed"},
    {0x04, "Hidden"},
    {0x08, "Notified"},
};

// Type values for Background Task Management items
const std::map<uint32_t, std::string> kTypeValues = {
    {0x00001, "user item"},
    {0x00002, "app"},
    {0x00004, "login item"},
    {0x00008, "agent"},
    {0x00010, "daemon"},
    {0x00020, "developer"},
    {0x00040, "spotlight"},
    {0x00800, "quicklook"},
    {0x80000, "curated"},
    {0x10000, "legacy"},
};

namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
};

// Helper function to convert disposition flags to string
std::string dispositionToString(uint32_t disposition) {
  std::vector<std::string> flags;
  for (const auto& pair : kDispositionValues) {
    if ((disposition & pair.first) != 0) {
      flags.push_back(pair.second);
    }
  }
  if (flags.empty()) {
    return "Unknown";
  }
  std::string result;
  for (size_t i = 0; i < flags.size(); ++i) {
    if (i > 0) {
      result += ", ";
    }
    result += flags[i];
  }
  return result;
}

// Helper function to convert type flags to string
std::string typeToString(uint32_t type) {
  std::vector<std::string> flags;
  for (const auto& pair : kTypeValues) {
    if ((type & pair.first) != 0) {
      flags.push_back(pair.second);
    }
  }
  if (flags.empty()) {
    return "Unknown";
  }
  std::string result;
  for (size_t i = 0; i < flags.size(); ++i) {
    if (i > 0) {
      result += ", ";
    }
    result += flags[i];
  }
  return result;
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

void parseItem(id item, QueryData& results) {
  if (item == nil) {
    return;
  }

  Row r;

  // Handle if item is an object (use KVC to access properties with exception
  // handling)
  id nameProperty = nil;
  id pathProperty = nil;
  id typeProperty = nil;
  id dispositionProperty = nil;

  @try {
    nameProperty = [item valueForKey:@"name"];
  } @catch (NSException* exception) {
    // Key doesn't exist or object doesn't support KVC for this key
    VLOG(1) << "parseItem: failed to get 'name' property: "
            << [[exception description] UTF8String];
  }

  @
  try {
    pathProperty = [item valueForKey:@"path"];
  } @catch (NSException* exception) {
    // Key doesn't exist or object doesn't support KVC for this key
    VLOG(1) << "parseItem: failed to get 'path' property: "
            << [[exception description] UTF8String];
  }

  @
  try {
    typeProperty = [item valueForKey:@"type"];
  } @catch (NSException* exception) {
    // Key doesn't exist or object doesn't support KVC for this key
  }

  @
  try {
    dispositionProperty = [item valueForKey:@"disposition"];
  } @catch (NSException* exception) {
    // Key doesn't exist or object doesn't support KVC for this key
  }

  if (nameProperty != nil) {
    r["name"] = std::string([[nameProperty description] UTF8String]);
  }

  if (pathProperty != nil) {
    r["path"] = std::string([[pathProperty description] UTF8String]);
  } else if (nameProperty != nil) {
    // Fallback to name if path is not available
    r["path"] = std::string([[nameProperty description] UTF8String]);
  }

  // Convert type property (numeric flags) to string
  if (typeProperty != nil) {
    if ([typeProperty respondsToSelector:@selector(unsignedIntValue)]) {
      uint32_t typeValue = [typeProperty unsignedIntValue];
      r["type"] = typeToString(typeValue);
    } else if ([typeProperty respondsToSelector:@selector(intValue)]) {
      uint32_t typeValue = static_cast<uint32_t>([typeProperty intValue]);
      r["type"] = typeToString(typeValue);
    } else {
      // Fallback to description if not a numeric type
      r["type"] = std::string([[typeProperty description] UTF8String]);
    }
  } else {
    r["type"] = "Background Task";
  }

  // Convert disposition property (numeric flags) to string
  if (dispositionProperty != nil) {
    if ([dispositionProperty respondsToSelector:@selector(unsignedIntValue)]) {
      uint32_t dispositionValue = [dispositionProperty unsignedIntValue];
      r["status"] = dispositionToString(dispositionValue);
    } else if ([dispositionProperty respondsToSelector:@selector(intValue)]) {
      uint32_t dispositionValue =
          static_cast<uint32_t>([dispositionProperty intValue]);
      r["status"] = dispositionToString(dispositionValue);
    } else {
      // Fallback to description if not a numeric type
      r["status"] = std::string([[dispositionProperty description] UTF8String]);
    }
  } else {
    r["status"] = "enabled";
  }

  r["source"] = "Background Task Management";

  // Only add row if we have at least a name
  if (!r["name"].empty()) {
    results.push_back(r);
  }
}

void parseItemsByUser(id items, QueryData& results) {
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
    parseItem(item, results);
  }
}

void genBtmStartupItems(QueryData& results) {
  const std::string kBtmDirectory =
      "/private/var/db/com.apple.backgroundtaskmanagement/";

  // Find the most recently modified .btm file using SQL query
  std::string query = "SELECT path FROM file WHERE directory = '" +
                      kBtmDirectory +
                      "' AND filename LIKE '%.btm' ORDER BY mtime DESC LIMIT 1";
  SQL sql(query);
  if (!sql.ok() || sql.rows().empty()) {
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
    // Load the BTM daemon into memory
    // This makes the Storage class available via NSClassFromString
    btmd = dlopen(BTM_DAEMON, RTLD_LAZY);

    if (btmd == NULL) {
      VLOG(1) << "Failed to load BTM daemon: " << dlerror();
    } else {
      VLOG(1) << "Successfully loaded BTM daemon";
    }

    // Step 1: Lookup the Storage and ItemRecord classes by name
    // This works because the daemon was loaded in the constructor
    Class StorageClass = NSClassFromString(@"Storage");
    Class ItemRecordClass = NSClassFromString(@"ItemRecord");

    if (StorageClass == nil) {
      VLOG(1) << "Storage class not found. Make sure BTM daemon is loaded.";
      return;
    }

    // Step 2: Load the BTM file data
    NSURL* btm_url = [NSURL
        fileURLWithPath:[NSString
                            stringWithUTF8String:most_recent_btm_file.c_str()]];
    NSError* error = nil;
    NSData* btm_data = [NSData dataWithContentsOfURL:btm_url
                                             options:0
                                               error:&error];

    if (btm_data == nil) {
      VLOG(1) << "Failed to load BTM file: "
              << [error.localizedDescription UTF8String];
      return;
    }

    // Step 3: Create an unarchiver for the BTM data
    NSKeyedUnarchiver* unarchiver =
        [[NSKeyedUnarchiver alloc] initForReadingFromData:btm_data
                                                    error:&error];
    if (unarchiver == nil) {
      VLOG(1) << "Failed to create NSKeyedUnarchiver: "
              << [error.localizedDescription UTF8String];
      return;
    }

    // Decode the Storage object. The key "store" is where the Storage object is
    // stored in the BTM file
    id store = nil;
    @try {
      // Use try/catch here because we don't control the ipmlementation of the
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
    for (id key in itemsByUser) {
      id value = itemsByUser[key];
      VLOG(1) << "genBtmStartupItems: itemsByUser entry key: "
              << [[key description] UTF8String];
      VLOG(1) << "genBtmStartupItems: itemsByUser entry value: "
              << [[value description] UTF8String];

      parseItemsByUser(value, results);
    }

    id mdmPayloadsByIdentifier = [store valueForKey:@"mdmPayloadsByIdentifier"];
    if (mdmPayloadsByIdentifier == nil ||
        ![mdmPayloadsByIdentifier isKindOfClass:[NSDictionary class]]) {
      LOG(ERROR) << "mdmPayloadsByIdentifier is not a dictionary";
      return;
    }
    for (id key in mdmPayloadsByIdentifier) {
      id value = mdmPayloadsByIdentifier[key];
      VLOG(1) << "genBtmStartupItems: mdmPayloadsByIdentifier entry key: "
              << [[key description] UTF8String];
      VLOG(1) << "genBtmStartupItems: mdmPayloadsByIdentifier entry value: "
              << [[value description] UTF8String];
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
