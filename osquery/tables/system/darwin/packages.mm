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

// Package BOM structure headers
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/packages.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kPkgReceiptPaths = {
    "/private/var/db/receipts/",
    "/Library/Receipts/",
    "/Library/Apple/System/Library/Receipts/"};

const std::vector<std::string> kPkgReceiptUserPaths = {
    "/Library/Receipts/",
};

const std::string kPkgInstallHistoryPath =
    "/Library/Receipts/InstallHistory.plist";

const std::map<std::string, std::string> kPkgReceiptKeys = {
    {"PackageIdentifier", "package_id"},
    {"PackageFileName", "package_filename"},
    {"PackageVersion", "version"},
    {"InstallPrefixPath", "location"},
    {"InstallDate", "install_time"},
    {"InstallProcessName", "installer_name"},
};

const std::map<std::string, std::string> kPKReceiptKeys{
    {"package_id", "packageIdentifier"},
    {"installer_name", "installProcessName"},
    {"install_time", "installDate"},
    {"location", "installPrefixPath"},
    {"version", "packageVersion"},
    {"path", "receiptStoragePaths"},
};

const std::map<std::string, std::string> kPkgInstallHistoryKeys = {
    {"date", "time"},
    {"displayName", "name"},
    {"displayVersion", "version"},
    {"processName", "source"},
    {"contentType", "content_type"},
};

BOM::BOM(const char* data, size_t size)
    : data_(data), size_(size), valid_(false) {
  if (size_ < sizeof(BOMHeader)) {
    // BOM structure header is invalid.
    return;
  }

  Header = (BOMHeader*)data_;
  if (std::string(Header->magic, 8) != "BOMStore") {
    // Header does not include expected magic value.
    return;
  }

  if (size_ < ntohl(Header->indexOffset) + sizeof(BOMBlockTable)) {
    // BOM block table is invalid.
    return;
  }

  Table = (BOMBlockTable*)(data_ + ntohl(Header->indexOffset));
  table_offset_ = ntohl(Header->indexOffset) + sizeof(BOMBlockTable);
  if (size_ < table_offset_ + ntohl(Table->count) * sizeof(BOMPointer)) {
    // BOM Pointer size/count is invalid.
    return;
  }

  if (size_ < ntohl(Header->varsOffset) + sizeof(BOMVars)) {
    // BOM variable table is invalid.
    return;
  }

  Vars = (BOMVars*)(data_ + ntohl(Header->varsOffset));
  vars_offset_ = ntohl(Header->varsOffset) + sizeof(BOMVars);
  if (size_ < vars_offset_ + ntohl(Vars->count) * sizeof(BOMVar)) {
    // BOM variables size/count is invalid.
    return;
  }
  valid_ = true;
}

/// Lookup a BOM pointer and optionally, it's size.
const char* BOM::getPointer(int index, size_t* _length) const {
  if (ntohl(index) >= ntohl(Table->count)) {
    // Requested pointer is out of range.
    return nullptr;
  }

  const BOMPointer* pointer = Table->blockPointers + ntohl(index);
  uint32_t addr = ntohl(pointer->address);
  uint32_t length = ntohl(pointer->length);
  if (addr > UINT32_MAX - length || size_ < addr + length) {
    // Address value is out of range.
    return nullptr;
  }

  if (_length != nullptr) {
    *_length = length;
  }
  return data_ + addr;
}

const BOMVar* BOM::getVariable(size_t* offset) const {
  if (offset == nullptr) {
    return nullptr;
  }

  if (size_ < vars_offset_ + *offset + sizeof(BOMVar)) {
    // Offset overflows the variable list.
    *offset = 0;
    return nullptr;
  }

  const BOMVar* var = (BOMVar*)((char*)Vars->list + *offset);
  if (var == nullptr) {
    *offset = 0;
    return nullptr;
  }

  *offset += sizeof(BOMVar) + var->length;
  if (size_ < vars_offset_ + *offset) {
    // Next offset overflows the variable list.
    *offset = 0;
    return nullptr;
  }

  return var;
}

const BOMPaths* BOM::getPaths(int index) const {
  size_t paths_size = 0;
  auto paths = (BOMPaths*)getPointer(index, &paths_size);
  if (paths == nullptr || paths_size < sizeof(BOMPaths)) {
    return nullptr;
  }

  // Check the number of indexes.
  if (paths_size < ntohs(paths->count) * sizeof(BOMPathIndices)) {
    return nullptr;
  }
  return paths;
}

void genBOMPaths(const std::string& path,
                 const BOM& bom,
                 const BOMPaths* paths,
                 QueryData& results) {
  std::map<uint32_t, std::string> filenames;
  std::map<uint32_t, uint32_t> parents;

  while (paths != nullptr) {
    for (unsigned j = 0; j < ntohs(paths->count); j++) {
      uint32_t index0 = paths->indices[j].index0;
      uint32_t index1 = paths->indices[j].index1;

      auto info1 = (const BOMPathInfo1*)bom.getPointer(index0);
      if (info1 == nullptr) {
        // Invalid BOMPathInfo1 structure.
        return;
      }

      auto info2 = (const BOMPathInfo2*)bom.getPointer(info1->index);
      if (info2 == nullptr) {
        // Invalid BOMPathInfo2 structure.
        return;
      }

      // Compute full name using pointer size.
      size_t file_size;
      auto file = (const BOMFile*)bom.getPointer(index1, &file_size);
      if (file == nullptr || file_size <= sizeof(BOMFile)) {
        // Invalid BOMFile structure or size out of bounds.
        return;
      }
      std::string filename(file->name, file_size - sizeof(BOMFile));
      filename = std::string(filename.c_str());

      // Maintain a lookup from BOM file index to filename.
      filenames[info1->id] = filename;
      if (file->parent) {
        parents[info1->id] = file->parent;
      }

      auto it = parents.find(info1->id);
      while (it != parents.end()) {
        filename = filenames[it->second] + "/" + filename;
        it = parents.find(it->second);
      }

      Row r;
      r["filepath"] = filename;
      r["uid"] = INTEGER(ntohl(info2->user));
      r["gid"] = INTEGER(ntohl(info2->group));
      r["mode"] = INTEGER(ntohs(info2->mode));
      r["size"] = INTEGER(ntohl(info2->size));
      r["modified_time"] = INTEGER(ntohl(info2->modtime));
      r["path"] = path;
      results.push_back(r);
    }

    if (paths->forward == htonl(0)) {
      return;
    } else {
      paths = bom.getPaths(paths->forward);
    }
  }
}

void genPackageBOM(const std::string& path, QueryData& results) {
  std::string content;
  // Read entire BOM file.
  if (!forensicReadFile(path, content).ok()) {
    return;
  }

  // Create a BOM representation.
  BOM bom(content.c_str(), content.size());
  if (!bom.isValid()) {
    return;
  }

  size_t var_offset = 0;
  for (unsigned i = 0; i < ntohl(bom.Vars->count); i++) {
    // Iterate through each BOM variable, a packed set of structures.
    auto var = bom.getVariable(&var_offset);
    if (var == nullptr || (char*)var->name == nullptr) {
      break;
    }

    size_t var_size;
    const char* var_data = bom.getPointer(var->index, &var_size);
    if (var_data == nullptr || var_size < sizeof(BOMTree) ||
        var_size < var->length) {
      break;
    }

    std::string name = std::string(var->name, var->length);
    if (name != "Paths") {
      // We only parse the BOM paths structure.
      continue;
    }

    const BOMTree* tree = (const BOMTree*)var_data;
    auto paths = bom.getPaths(tree->child);
    while (paths != nullptr && paths->isLeaf == htons(0)) {
      if ((BOMPathIndices*)paths->indices == nullptr) {
        break;
      }
      paths = bom.getPaths(paths->indices[0].index0);
    }

    genBOMPaths(path, bom, paths, results);
    break;
  }
}

QueryData genPackageBOM(QueryContext& context) {
  QueryData results;
  if (context.constraints["path"].exists(EQUALS)) {
    // If an explicit path was given, generate and return.
    auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path : paths) {
      genPackageBOM(path, results);
    }
  }

  return results;
}

void genPackageReceipt(const std::string& path, QueryData& results) {
  auto receipt = SQL::selectAllFrom("plist", "path", EQUALS, path);
  if (receipt.size() == 0) {
    // Fail if the file could not be plist-parsed.
    return;
  }

  Row r;
  r["path"] = path;
  for (const auto& row : receipt) {
    if (kPkgReceiptKeys.count(row.at("key")) > 0) {
      r[kPkgReceiptKeys.at(row.at("key"))] = row.at("value");
    }
  }

  if (!r["package_id"].empty()) {
    results.push_back(std::move(r));
  }
}

/**
 * @brief Try to use PackageKit to list installed packages.
 *
 * This method may return false, indicating that a fall-back brute-force method
 * should be tried.
 *
 * @param results the output data.
 * @return true of the APIs succeeded, otherwise false.
 */
static inline bool genPackagesFromPackageKit(QueryData& results) {
  @autoreleasepool {
    auto bundle_url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault,
        CFSTR("/System/Library/PrivateFrameworks/PackageKit.framework"),
        kCFURLPOSIXPathStyle,
        true);
    if (bundle_url == nullptr) {
      return false;
    }

    auto bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
    CFRelease(bundle_url);
    if (bundle == nullptr) {
      return false;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

    NSArray* packages = nullptr;
    if (CFBundleLoadExecutable(bundle)) {
      auto cls = NSClassFromString(@"PKReceipt");
      if (cls != nil) {
        SEL sls = NSSelectorFromString(@"receiptsOnVolumeAtPath:");
        @try {
          id receipts = [cls performSelector:sls withObject:@"/"];
          if ([receipts isKindOfClass:[NSArray class]]) {
            packages = (NSArray*)receipts;
          }
        } @catch (NSException* exception) {
          // The class did not respond to the selector.
        }
      }
      CFBundleUnloadExecutable(bundle);
    }

    CFRelease(bundle);

    if (packages == nullptr) {
      // No packages were found.
      return false;
    }

    for (id pkg in packages) {
      Row r;
      for (auto& pm : kPKReceiptKeys) {
        @try {
          auto selector = [NSString stringWithUTF8String:pm.second.c_str()];
          auto sls = NSSelectorFromString(selector);
          id value = [pkg performSelector:sls];

          if ([value isKindOfClass:[NSString class]]) {
            r[pm.first] = [value UTF8String];
          } else if ([value isKindOfClass:[NSDate class]]) {
            auto seconds =
                [[NSNumber alloc] initWithDouble:[value timeIntervalSince1970]];
            r[pm.first] = [[seconds stringValue] UTF8String];
          } else if ([value isKindOfClass:[NSArray class]]) {
            for (id first in value) {
              r[pm.first] = [first UTF8String];
              break;
            }
          }
        } @catch (NSException* ex) {
          // The class did not respond to the selector.
          // The type of data replied may have changes.
          VLOG(1) << "Could not select " << pm.second << ": "
                  << [[ex name] UTF8String];
        }
      }
      results.push_back(r);
    }
#pragma clang diagnostic pop
  }
  // Add a final assumption that PackageKit will have found 1 package.
  return (results.empty()) ? false : true;
}

/**
 * @brief Iterate over each well-known system absolute directory of receipts.
 *
 * This is not the absolute correct way to enumerate receipts, but works.
 * Consider this method a brute-force low-fidelity option if the private
 * PackageKit APIs fail.
 *
 * @param results the output data.
 */
static inline void genPackagesFromPlists(QueryData& results) {
  for (const auto& path : kPkgReceiptPaths) {
    std::vector<std::string> receipts;
    if (resolveFilePattern(path + "%.plist", receipts)) {
      for (const auto& receipt : receipts) {
        genPackageReceipt(receipt, results);
      }
    }
  }

  // User home directories may include user-specific receipt lists.
  auto users = getHomeDirectories();
  for (const auto& user : users) {
    for (const auto& path : kPkgReceiptUserPaths) {
      std::vector<std::string> receipts;
      fs::path receipt_path = user / path;
      if (resolveFilePattern(receipt_path.string() + "%.plist", receipts)) {
        for (const auto& receipt : receipts) {
          genPackageReceipt(receipt, results);
        }
      }
    }
  }
}

QueryData genPackageReceipts(QueryContext& context) {
  QueryData results;
  if (context.constraints["path"].exists(EQUALS)) {
    // If an explicit path was given, generate and return.
    auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path : paths) {
      genPackageReceipt(path, results);
    }
    return results;
  } else if (context.constraints["package_filename"].exists(EQUALS)) {
    auto files = context.constraints["package_filename"].getAll(EQUALS);
    for (const auto& file : files) {
      // Assume the filename can be within any of the system or user paths.
      for (const auto& search_path : kPkgReceiptPaths) {
        genPackageReceipt((fs::path(search_path) / file).string(), results);
      }
      for (const auto& search_path : kPkgReceiptUserPaths) {
        genPackageReceipt((fs::path(search_path) / file).string(), results);
      }
    }
    return results;
  }

  if (!genPackagesFromPackageKit(results)) {
    VLOG(1) << "Cannot list package receipts from PackageKit";
    genPackagesFromPlists(results);
  }

  return results;
}

void genPkgInstallHistoryEntry(const pt::ptree& entry, QueryData& results) {
  Row r;
  for (const auto& it : kPkgInstallHistoryKeys) {
    r[it.second] = entry.get(it.first, "");
  }

  // some packages do not set packageIdentifiers, allow it to be
  // empty. Empirically this seems to be os packages, but we can't
  // assume that.
  auto it = entry.find("packageIdentifiers");
  if (it != entry.not_found()) {
    for (const auto& package_identifier : it->second) {
      r["package_id"] = package_identifier.second.get<std::string>("");
      results.push_back(r);
    }
  } else {
    // push_back for the nil packageIdentifiers case
    results.push_back(r);
  }
}

QueryData genPackageInstallHistory(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  // The osquery::parsePlist method will reset/clear a property tree.
  // Keeping the data structure in a larger scope preserves allocations
  // between similar-sized trees.
  if (!osquery::parsePlist(kPkgInstallHistoryPath, tree).ok()) {
    TLOG << "Error parsing install history plist: " << kPkgInstallHistoryPath;
    return results;
  }

  if (tree.count("root") != 0) {
    for (const auto& it : tree.get_child("root")) {
      genPkgInstallHistoryEntry(it.second, results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
