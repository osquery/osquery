/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/tables/system/darwin/keychain.h"

namespace osquery {
namespace tables {

const std::vector<CFTypeRef> kKeychainItemTypes = {
    kSecClassGenericPassword,
    kSecClassCertificate,
    kSecClassKey,
    kSecClassIdentity,
};

const std::map<SecItemAttr, std::string> kKeychainItemAttrs = {
    {kSecLabelItemAttr, "label"},
    {kSecDescriptionItemAttr, "description"},
    {kSecCommentItemAttr, "comment"},
    {kSecCreationDateItemAttr, "created"},
    {kSecModDateItemAttr, "modified"},
};

const std::map<SecItemClass, std::string> kKeychainItemClasses = {
    {kSecGenericPasswordItemClass, "password"},
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
    SecKeychainItemCopyAttributesAndData(
        item, &info, &item_class, &attr_list, 0, nullptr);

    if (attr_list != nullptr) {
      // Expect each specific tag to return string data.
      for (size_t i = 0; i < attr_list->count; ++i) {
        SecKeychainAttribute* attr = &attr_list->attr[i];
        if (attr->length > 0) {
          r[attr_tag.second] = std::string((char*)attr->data, attr->length);
        }
      }
      SecKeychainItemFreeAttributesAndData(attr_list, nullptr);
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

  // Allow the caller to set an explicit certificate (keychain) search path.
  std::set<std::string> keychain_paths;
  if (context.constraints["path"].exists(EQUALS)) {
    keychain_paths = context.constraints["path"].getAll(EQUALS);
  } else {
    keychain_paths = getKeychainPaths();
  }

  for (const auto& item_type : kKeychainItemTypes) {
    CFArrayRef items = CreateKeychainItems(keychain_paths, item_type);
    if (items == nullptr) {
      continue;
    }
    auto count = CFArrayGetCount(items);
    for (CFIndex i = 0; i < count; i++) {
      genKeychainItem((SecKeychainItemRef)CFArrayGetValueAtIndex(items, i),
                      results);
    }

    CFRelease(items);
  }

  return results;
}
}
}
