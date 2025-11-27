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

// Constructor: loads the BTM daemon when the library is loaded
namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
};

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
    unarchiver.decodingFailurePolicy = NSDecodingFailurePolicyRaiseException;

    // Step 4: Deserialize the Storage object from the BTM file
    id store = nil;

    @try {
      // Decode the Storage object using the class we found
      // The key "store" is where the Storage object is stored in the BTM file
      store = [unarchiver decodeObjectOfClass:StorageClass forKey:@"store"];
      [unarchiver finishDecoding];

      if (store == nil) {
        VLOG(1) << "Failed to decode store object from BTM file";
        return;
      }
    } @catch (NSException* exception) {
      VLOG(1) << "Failed to deserialize Storage: "
              << [exception.description UTF8String];
      return;
    }

    // Process the store object - handle Storage class
    NSDictionary* items_dict = nil;
    if (StorageClass != nil && [store isKindOfClass:StorageClass]) {
      id storage_obj = store;
      // Combine items from both properties using KVC
      NSMutableDictionary* combined_items = [NSMutableDictionary dictionary];
      id itemsByUser = [storage_obj valueForKey:@"itemsByUserIdentifier"];
      id mdmPayloads = [storage_obj valueForKey:@"mdmPayloadsByIdentifier"];
      if (itemsByUser != nil &&
          [itemsByUser isKindOfClass:[NSDictionary class]]) {
        [combined_items addEntriesFromDictionary:(NSDictionary*)itemsByUser];
      }
      if (mdmPayloads != nil &&
          [mdmPayloads isKindOfClass:[NSDictionary class]]) {
        [combined_items addEntriesFromDictionary:(NSDictionary*)mdmPayloads];
      }
      items_dict = combined_items;
      VLOG(1) << "genBtmStartupItems: Storage object has " << [items_dict count]
              << " items";
    } else if ([store isKindOfClass:[NSDictionary class]]) {
      items_dict = (NSDictionary*)store;
      VLOG(1) << "genBtmStartupItems: store has " << [items_dict count]
              << " entries";
    } else {
      VLOG(1) << "genBtmStartupItems: store is unexpected type: "
              << [[store className] UTF8String];
      return;
    }

    // Process items from the dictionary
    for (id key in items_dict) {
      id value = items_dict[key];
      VLOG(1) << "genBtmStartupItems: value: "
              << [[value description] UTF8String];
      VLOG(1) << "genBtmStartupItems: store entry key: "
              << [[key description] UTF8String];

      // Handle arrays that may contain ItemRecord objects
      NSArray* items_array = nil;
      if ([value isKindOfClass:[NSArray class]]) {
        items_array = (NSArray*)value;
      } else if ([value isKindOfClass:[NSDictionary class]]) {
        // If it's a dictionary, treat it as a single entry
        items_array = @[ value ];
      } else if (ItemRecordClass != nil &&
                 [value isKindOfClass:ItemRecordClass]) {
        // If it's an ItemRecord, wrap it in an array
        items_array = @[ value ];
      } else {
        continue;
      }

      // Process each item in the array
      for (id item in items_array) {
        NSDictionary* entry = nil;
        id item_record = nil;

        // Convert ItemRecord to dictionary-like access, or use dictionary
        // directly
        if (ItemRecordClass != nil && [item isKindOfClass:ItemRecordClass]) {
          item_record = item;
        } else if ([item isKindOfClass:[NSDictionary class]]) {
          entry = (NSDictionary*)item;
        } else {
          continue;
        }

        // Extract path information
        id path_obj = nil;
        if (entry != nil) {
          path_obj = entry[@"path"];
          if (path_obj == nil) {
            // Try other possible keys
            path_obj = entry[@"URL"];
            if (path_obj == nil) {
              path_obj = entry[@"url"];
              if (path_obj == nil) {
                path_obj = entry[@"Path"];
              }
            }
          }
        } else if (item_record != nil) {
          // Access ItemRecord properties using KVC
          path_obj = [item_record valueForKey:@"path"];
          if (path_obj == nil) {
            path_obj = [item_record valueForKey:@"URL"];
          }
        }

        std::string path;
        if ([path_obj isKindOfClass:[NSString class]]) {
          path = [path_obj UTF8String];
        } else if ([path_obj isKindOfClass:[NSURL class]]) {
          path = [[(NSURL*)path_obj path] UTF8String];
        }

        if (!path.empty() && (path[0] == '/' || path.find("file://") == 0)) {
          // Handle file:// URLs
          if (path.find("file://") == 0) {
            path = path.substr(7);
            // URL decode if needed (simple case - just remove %20 -> space)
            size_t pos = 0;
            while ((pos = path.find("%20", pos)) != std::string::npos) {
              path.replace(pos, 3, " ");
              pos += 1;
            }
          }

          // Filter for executables, plist files, or app bundles
          bool is_valid = false;
          if (path.find(".plist") != std::string::npos ||
              path.find(".app/") != std::string::npos ||
              path.find("/Contents/MacOS/") != std::string::npos ||
              (path[0] == '/' && fs::path(path).extension().empty() &&
               path.find("/bin/") != std::string::npos)) {
            is_valid = true;
          }

          if (is_valid) {
            Row r;
            r["type"] = "Startup Item";
            r["source"] = kBtmDirectory;

            // Extract status from disposition
            std::string status = "enabled";
            id disposition_obj = nil;
            if (entry != nil) {
              disposition_obj = entry[@"disposition"];
            } else if (item_record != nil) {
              disposition_obj = [item_record valueForKey:@"disposition"];
            }

            if (disposition_obj != nil) {
              int disposition = -1;
              if ([disposition_obj isKindOfClass:[NSNumber class]]) {
                disposition = [disposition_obj intValue];
              } else if ([disposition_obj isKindOfClass:[NSString class]]) {
                auto result =
                    tryTo<int>(std::string([disposition_obj UTF8String]), 10);
                if (!result.isError()) {
                  disposition = result.get();
                }
              }

              if (disposition >= 0) {
                if (disposition & 0x01) {
                  status = "enabled";
                } else {
                  status = "disabled";
                }
              }
            }

            r["status"] = status;
            r["path"] = path;
            r["name"] = fs::path(path).filename().string();
            results.push_back(r);
          }
        }
      }
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
