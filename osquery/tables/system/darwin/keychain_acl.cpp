/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <Security/Security.h>

#include <boost/format.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/join.h>

namespace osquery {
namespace tables {

typedef struct {
  std::string keychain_path;
  std::string label;
} KeychainItemMetadata;

typedef struct {
  std::vector<std::string> authorizations;
  std::string description;
  std::vector<std::string> applications;
} KeychainItemACL;

const std::map<CSSM_ACL_AUTHORIZATION_TAG, std::string> kACLAuthorizationTags =
    {
        {CSSM_ACL_AUTHORIZATION_ANY, "any"},
        {CSSM_ACL_AUTHORIZATION_LOGIN, "login"},
        {CSSM_ACL_AUTHORIZATION_GENKEY, "genkey"},
        {CSSM_ACL_AUTHORIZATION_DELETE, "delete"},
        {CSSM_ACL_AUTHORIZATION_EXPORT_WRAPPED, "export_wrapped"},
        {CSSM_ACL_AUTHORIZATION_EXPORT_CLEAR, "export_clear"},
        {CSSM_ACL_AUTHORIZATION_IMPORT_WRAPPED, "import_wrapped"},
        {CSSM_ACL_AUTHORIZATION_IMPORT_CLEAR, "import_clear"},
        {CSSM_ACL_AUTHORIZATION_SIGN, "sign"},
        {CSSM_ACL_AUTHORIZATION_ENCRYPT, "encrypt"},
        {CSSM_ACL_AUTHORIZATION_DECRYPT, "decrypt"},
        {CSSM_ACL_AUTHORIZATION_MAC, "mac"},
        {CSSM_ACL_AUTHORIZATION_DERIVE, "derive"},
        {CSSM_ACL_AUTHORIZATION_DBS_CREATE, "dbs_create"},
        {CSSM_ACL_AUTHORIZATION_DBS_DELETE, "dbs_delete"},
        {CSSM_ACL_AUTHORIZATION_DB_READ, "db_read"},
        {CSSM_ACL_AUTHORIZATION_DB_INSERT, "db_insert"},
        {CSSM_ACL_AUTHORIZATION_DB_MODIFY, "db_modify"},
        {CSSM_ACL_AUTHORIZATION_DB_DELETE, "db_delete"},
        {CSSM_ACL_AUTHORIZATION_CHANGE_ACL, "change_acl"},
        {CSSM_ACL_AUTHORIZATION_CHANGE_OWNER, "change_owner"},
};

Status parseKeychainItemACLEntry(SecACLRef acl,
                                 std::vector<KeychainItemACL>& acls) {
  KeychainItemACL acl_data;
  OSStatus os_status;

  uint32 acl_tag_size = 64;
  std::vector<CSSM_ACL_AUTHORIZATION_TAG> tags(acl_tag_size);
  OSQUERY_USE_DEPRECATED(
      os_status = SecACLGetAuthorizations(acl, tags.data(), &acl_tag_size));
  if (os_status != noErr) {
    return Status(os_status, "Could not get ACL authorizations");
  }

  for (size_t tag_index = 0; tag_index < acl_tag_size; ++tag_index) {
    CSSM_ACL_AUTHORIZATION_TAG tag = tags[tag_index];
    if (kACLAuthorizationTags.find(tag) != kACLAuthorizationTags.end()) {
      acl_data.authorizations.push_back(kACLAuthorizationTags.at(tag));
    }
  }
  CFStringRef description = nullptr;
  CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR prompt_selector = {};
  CFArrayRef application_list = nullptr;
  OSQUERY_USE_DEPRECATED(
      os_status = SecACLCopySimpleContents(
          acl, &application_list, &description, &prompt_selector));
  if (os_status != noErr) {
    return Status(os_status, "Could not copy ACL content");
  }

  if (description != nullptr) {
    acl_data.description = stringFromCFString(description);
    CFRelease(description);
  }

  if (application_list != nullptr) {
    CFIndex app_count = CFArrayGetCount(application_list);
    for (CFIndex app_index = 0; app_index < app_count; app_index++) {
      SecTrustedApplicationRef app =
          (SecTrustedApplicationRef)CFArrayGetValueAtIndex(application_list,
                                                           app_index);
      CFDataRef data = nullptr;
      os_status = SecTrustedApplicationCopyData(app, &data);
      if (os_status != noErr || data == nullptr) {
        CFRelease(application_list);
        if (data != nullptr) {
          // To be very safe, assume data may have been allocated on error.
          CFRelease(data);
        }
        return Status(os_status, "Could not copy trusted application data");
      }

      const UInt8* bytes = CFDataGetBytePtr(data);
      if (bytes != nullptr && bytes[0] == '/') {
        acl_data.applications.push_back(std::string((const char*)bytes));
      }
      CFRelease(data);
    }
    CFRelease(application_list);
  }

  acls.push_back(acl_data);
  return Status::success();
}

Status parseKeychainItemACL(SecAccessRef access,
                            std::vector<KeychainItemACL>& acls) {
  OSStatus os_status;
  CFArrayRef acl_list = nullptr;
  os_status = SecAccessCopyACLList(access, &acl_list);
  if (os_status != noErr || acl_list == nullptr) {
    if (acl_list != nullptr) {
      CFRelease(acl_list);
    }
    return Status(os_status, "Could not copy ACL list");
  }

  auto acl_count = CFArrayGetCount(acl_list);
  for (CFIndex i = 0; i < acl_count; i++) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, i);
    auto s = parseKeychainItemACLEntry(acl, acls);
    if (!s.ok()) {
      TLOG << "Error parsing individual ACL entry: " << s.toString();
      continue;
    }
  }

  CFRelease(acl_list);
  return Status::success();
}

static std::string attributeBufferToString(const void* data, UInt32 length) {
  std::stringstream stream;
  uint8* p = (uint8*)data;
  while (length--) {
    char ch = *p++;
    if (ch >= ' ' && ch <= '~' && ch != '\\') {
      stream << (char)ch;
    } else {
      stream << std::hex << ch;
    }
  }
  return stream.str();
}

Status genKeychainACLAppsForEntry(SecKeychainRef keychain,
                                  SecKeychainItemRef item,
                                  const std::string& path,
                                  QueryData& results) {
  KeychainItemMetadata item_metadata;
  item_metadata.keychain_path = path;

  SecItemClass item_class;
  SecKeychainItemCopyAttributesAndData(
      item, nullptr, &item_class, nullptr, nullptr, nullptr);

  SecAccessRef access = nullptr;
  OSStatus os_status;
  Status s;
  os_status = SecKeychainItemCopyAccess(item, &access);
  if (os_status == errSecNoAccessForItem || access == nullptr) {
    if (access != nullptr) {
      CFRelease(access);
    }
    return Status(os_status, "No ACLs for keychain item");
  }

  std::vector<KeychainItemACL> acl;
  s = parseKeychainItemACL(access, acl);
  CFRelease(access);
  if (!s.ok()) {
    return s;
  }

  UInt32 item_id;
  switch (item_class) {
  case kSecInternetPasswordItemClass:
    item_id = CSSM_DL_DB_RECORD_INTERNET_PASSWORD;
    break;
  case kSecGenericPasswordItemClass:
    item_id = CSSM_DL_DB_RECORD_GENERIC_PASSWORD;
    break;
  // ashp case
  case 0x61736870:
    item_id = CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD;
    break;
  default:
    item_id = item_class;
    break;
  }

  SecKeychainAttributeInfo* info = nullptr;
  SecKeychainAttributeInfoForItemID(keychain, item_id, &info);

  SecKeychainAttributeList* attr_list = nullptr;
  os_status = SecKeychainItemCopyAttributesAndData(
      item, info, &item_class, &attr_list, nullptr, nullptr);
  if (os_status != noErr || attr_list == nullptr || info == nullptr) {
    if (attr_list != nullptr) {
      SecKeychainItemFreeAttributesAndData(attr_list, nullptr);
    }
    if (info != nullptr) {
      SecKeychainFreeAttributeInfo(info);
    }
    return Status(os_status,
                  "Could not copy attributes and data from the keychain");
  }

  // Bail if the number of elements from the info/Attr list do not match.
  if (info->count != attr_list->count) {
    SecKeychainItemFreeAttributesAndData(attr_list, nullptr);
    SecKeychainFreeAttributeInfo(info);
    return Status(1, "Info and attributes do not match");
  }

  for (size_t i = 0; i < info->count; ++i) {
    SecKeychainAttribute* attribute = &attr_list->attr[i];
    if (attribute->length == 0) {
      continue;
    }

    UInt32 tag = info->tag[i];
    if (tag == 7) {
      item_metadata.label =
          attributeBufferToString(attribute->data, attribute->length);
    }
  }

  // Finally, release/free the info/Attr lists.
  SecKeychainItemFreeAttributesAndData(attr_list, nullptr);
  SecKeychainFreeAttributeInfo(info);

  for (const auto& acl_data : acl) {
    for (const auto& app_path : acl_data.applications) {
      Row r;
      r["keychain_path"] = item_metadata.keychain_path;
      r["label"] = item_metadata.label;
      r["authorizations"] = join(acl_data.authorizations, " ");
      r["description"] = acl_data.description;
      r["path"] = app_path;
      results.push_back(r);
    }
  }

  return Status::success();
}

Status genKeychainACLApps(const std::string& path, QueryData& results) {
  SecKeychainRef keychain = nullptr;
  OSStatus os_status = 0;
  os_status = SecKeychainOpen(path.c_str(), &keychain);
  if (os_status != noErr || keychain == nullptr) {
    if (keychain != nullptr) {
      CFRelease(keychain);
    }
    return Status(os_status, "Could not open the keychain at " + path);
  }

  SecKeychainSearchRef search = nullptr;
  OSQUERY_USE_DEPRECATED(
      os_status = SecKeychainSearchCreateFromAttributes(
          keychain, (SecItemClass)CSSM_DL_DB_RECORD_ANY, nullptr, &search));
  if (os_status != noErr || search == nullptr) {
    if (search != nullptr) {
      CFRelease(search);
    }
    CFRelease(keychain);
    return Status(os_status,
                  "Could not pull keychain items from the search API");
  }

  SecKeychainItemRef item = nullptr;
  while (true) {
    OSQUERY_USE_DEPRECATED(os_status =
                               SecKeychainSearchCopyNext(search, &item));
    if (os_status != noErr || item == nullptr) {
      break;
    }

    auto s = genKeychainACLAppsForEntry(keychain, item, path, results);
    CFRelease(item);
    if (!s.ok()) {
      TLOG << "Error parsing keychain at " << path << ": " << s.toString();
    }
  }

  CFRelease(keychain);
  CFRelease(search);
  return Status::success();
}

QueryData genKeychainACLApps(QueryContext& context) {
  QueryData results;

  SecKeychainSetUserInteractionAllowed(false);
  for (const auto& path : getKeychainPaths()) {
    std::vector<std::string> ls_results;
    auto list_status = listFilesInDirectory(path, ls_results, false);
    if (!list_status.ok()) {
      TLOG << "Could not list files in " << path << ": "
           << list_status.toString();
    }
    for (const auto& keychain : ls_results) {
      TLOG << "Checking directory: " << keychain;
      auto gen_status = genKeychainACLApps(keychain, results);
      if (!gen_status.ok()) {
        TLOG << "Could not list items from " << keychain << ": "
             << gen_status.toString();
      }
    }
  }
  SecKeychainSetUserInteractionAllowed(true);

  return results;
}
}
}
