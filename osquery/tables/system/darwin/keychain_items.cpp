/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/hex.hpp>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>

namespace osquery {
namespace tables {

// The table key for Keychain cache access.
static const KeychainTable KEYCHAIN_TABLE = KeychainTable::KEYCHAIN_ITEMS;

const std::vector<CFTypeRef> kKeychainItemTypes = {
    kSecClassGenericPassword,
    kSecClassInternetPassword,
    kSecClassCertificate,
    kSecClassKey,
    kSecClassIdentity,
};

const std::map<FourCharCode, std::string> kKeychainItemAttrs = {
    {kSecLabelItemAttr, "label"},
    {kSecKeyPrintName, "label"},
    {kSecDescriptionItemAttr, "description"},
    {kSecKeyLabel, "pk_hash"},
    {kSecPublicKeyHashItemAttr, "pk_hash"},
    {kSecCommentItemAttr, "comment"},
    {kSecAccountItemAttr, "account"},
    {kSecCreationDateItemAttr, "created"},
    {kSecModDateItemAttr, "modified"},
};

const std::map<SecItemClass, std::string> kKeychainItemClasses = {
    {kSecGenericPasswordItemClass, "password"},
    {kSecInternetPasswordItemClass, "internet password"},
    {kSecCertificateItemClass, "certificate"},
    {kSecPublicKeyItemClass, "public key"},
    {kSecPrivateKeyItemClass, "private key"},
    {kSecSymmetricKeyItemClass, "symmetric key"}};

void genKeychainItem(const SecKeychainItemRef& item, QueryData& results) {
  Row r;

  // Create an info structure with 1 tag, then iterate over setting the tag
  // type to assure maximum compatibility with the various Keychain items.
  SecKeychainAttributeInfo info;
  UInt32 tags[1];
  info.count = sizeof(tags) / sizeof(UInt32);
  info.tag = tags;
  info.format = nullptr;

  SecItemClass item_class;
  SecKeychainAttributeList* attr_list = nullptr;

  // Any tag that does not exist for the item will prevent the entire result.
  for (const auto& attr_tag : kKeychainItemAttrs) {
    tags[0] = attr_tag.first;

    OSStatus os_status;
    OSQUERY_USE_DEPRECATED(
        os_status = SecKeychainItemCopyAttributesAndData(
            item, &info, &item_class, &attr_list, nullptr, nullptr));

    if (os_status == errSecNoSuchAttr) {
      // This attr does not exist, skip it.
      continue;
    } else if (os_status != errSecSuccess) {
      // If this keychain item is not valid then don't add it to results.
      return;
    }

    if (attr_list != nullptr) {
      // Expect each specific tag to return string data.
      for (size_t i = 0; i < attr_list->count; ++i) {
        SecKeychainAttribute* attr = &attr_list->attr[i];
        if (attr->length > 0) {
          auto raw_data = std::string((char*)attr->data, attr->length);
          std::string encoded;

          // key hashes need to be hex encoded
          if (attr_tag.first == kSecPublicKeyHashItemAttr ||
              attr_tag.first == kSecKeyLabel) {
            // skip for symmetric keys since they do not have a public key
            if (item_class != kSecSymmetricKeyItemClass) {
              boost::algorithm::hex(raw_data.begin(),
                                    raw_data.end(),
                                    std::back_inserter(encoded));
            }
          } else {
            encoded = raw_data;
          }

          r[attr_tag.second] = encoded;
        }
      }
      OSQUERY_USE_DEPRECATED(
          SecKeychainItemFreeAttributesAndData(attr_list, nullptr));
      attr_list = nullptr;
    }
  }

  // The keychain item class is obtained each time and will be consistent.
  if (kKeychainItemClasses.count(item_class) > 0) {
    r["type"] = kKeychainItemClasses.at(item_class);
  }

  r["path"] = getKeychainPath(item);
  results.push_back(r);
}

QueryData genKeychainItems(QueryContext& context) {
  QueryData results;

  // Lock keychain access to 1 table/thread at a time.
  std::unique_lock<decltype(keychainMutex)> lock(keychainMutex);

  // Allow the caller to set an explicit certificate (keychain) search path.
  std::set<std::string> keychain_paths;
  if (context.constraints["path"].exists(EQUALS)) {
    keychain_paths = context.constraints["path"].getAll(EQUALS);
  } else {
    keychain_paths = getKeychainPaths();
  }

  // Since we are using a cache for each keychain file, we must process
  // certificates one keychain file at a time.
  std::set<std::string> expanded_paths = expandPaths(keychain_paths);
  for (const auto& path : expanded_paths) {
    // Check whether path is valid
    boost::system::error_code ec;
    auto source =
        boost::filesystem::canonical(boost::filesystem::path(path), ec);
    if (ec.failed() || !is_regular_file(source, ec) || ec.failed()) {
      // File does not exist or user does not have access. Don't log here to
      // reduce noise.
      continue;
    }

    // Check cache
    bool err = false;
    std::string hash;
    bool hit = keychainCache.Read(source, KEYCHAIN_TABLE, hash, results, err);
    if (err) {
      TLOG << "Could not read the file at " << path << "" << ec.message();
      continue;
    }
    if (hit) {
      continue;
    }

    // Cache miss. We need to generate new results.
    SecKeychainRef keychain = nullptr;
    OSStatus status;
    OSQUERY_USE_DEPRECATED(status = SecKeychainOpen(source.c_str(), &keychain));
    if (status != errSecSuccess || keychain == nullptr) {
      if (keychain != nullptr) {
        CFRelease(keychain);
      }
      // Cache an empty result to prevent the above API call in the future.
      keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
      continue;
    }

    auto keychains = CFArrayCreateMutable(nullptr, 1, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(keychains, keychain);
    QueryData new_results;
    for (const auto& item_type : kKeychainItemTypes) {
      std::set<std::string> temp_paths;
      temp_paths.insert(path);
      CFArrayRef items = CreateKeychainItems(keychains, item_type);
      if (items == nullptr) {
        // Cache an empty result to prevent the above API calls in the future.
        keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
        continue;
      }
      auto count = CFArrayGetCount(items);
      for (CFIndex i = 0; i < count; i++) {
        genKeychainItem((SecKeychainItemRef)CFArrayGetValueAtIndex(items, i),
                        new_results);
      }

      CFRelease(items);
    }
    CFRelease(keychains);

    // Update cache and results
    keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
    results.insert(results.end(), new_results.begin(), new_results.end());
  }

  if (FLAGS_keychain_access_cache) {
    TLOG << "Total Keychain Cache entries: " << keychainCache.Size();
  }

  return results;
}
}
}
