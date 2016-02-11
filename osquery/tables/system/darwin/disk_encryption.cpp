/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <membership.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/sql.h>

#include "osquery/tables/system/darwin/iokit_utils.h"

namespace osquery {
namespace tables {

// AES-XTS is the only block algorithm supported by FileVault2
// https://opensource.apple.com/source/xnu/xnu-2782.1.97/libkern/crypto/corecrypto_aesxts.c
const std::string kEncryptionType = "AES-XTS";
const std::string kDeviceNamePrefix = "/dev/";

// kCoreStorageIsEncryptedKey is not publicly defined
// or documented because CoreStorage is a private framework
#define kCoreStorageIsEncryptedKey_ "CoreStorage Encrypted"
#define kIODeviceTreeChosenPath_ "IODeviceTree:/chosen"

Status genUnlockIdent(CFDataRef& uuid) {
  auto chosen =
      IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreeChosenPath_);
  if (chosen == MACH_PORT_NULL) {
    return Status(1, "Could not open IOKit DeviceTree");
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      chosen, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(chosen);

  if (kr != KERN_SUCCESS) {
    return Status(1, "Could not get IOKit chosen properties");
  }

  if (properties == nullptr) {
    return Status(1, "Could not load IOKit properties");
  }

  CFTypeRef unlock_ident = nullptr;
  if (CFDictionaryGetValueIfPresent(
          properties, CFSTR("efilogin-unlock-ident"), &unlock_ident)) {
    if (CFGetTypeID(unlock_ident) != CFDataGetTypeID()) {
      return Status(1, "Unexpected data type for unlock ident");
    }
    uuid = CFDataCreateCopy(kCFAllocatorDefault, (CFDataRef)unlock_ident);
    if (uuid == nullptr) {
      return Status(1, "Could not get UUID");
    }
    CFRelease(properties);
    return Status(0, "ok");
  }

  return Status(1, "Could not get unlock ident");
}

Status genUid(id_t& uid, uuid_string_t& uuid_str) {
  CFDataRef uuid = nullptr;
  if (!genUnlockIdent(uuid).ok()) {
    return Status(1, "Could not get unlock ident");
  }

  CFDataGetBytes(uuid, CFRangeMake(0, CFDataGetLength(uuid)), (UInt8*)uuid_str);
  uuid_t uuidT = {0};
  if (uuid_parse(uuid_str, uuidT) != 0) {
    return Status(1, "Could not parse UUID");
  }

  // id_type >=0 are all valid id types
  int id_type = -1;
  if (mbr_uuid_to_id(uuidT, &uid, &id_type) != 0 && id_type != ID_TYPE_UID) {
    return Status(1, "Could not get uid from uuid");
  }

  return Status(0, "ok");
}

void genFDEStatusForBSDName(const std::string& bsd_name,
                            const std::string& uuid,
                            QueryData& results) {

  auto matching_dict =
      IOBSDNameMatching(kIOMasterPortDefault, kNilOptions, bsd_name.c_str());
  if (matching_dict == nullptr) {
    return;
  }

  auto service =
      IOServiceGetMatchingService(kIOMasterPortDefault, matching_dict);
  if (!service) {
    return;
  }

  CFMutableDictionaryRef properties;
  if (IORegistryEntryCreateCFProperties(
          service, &properties, kCFAllocatorDefault, kNilOptions) !=
      KERN_SUCCESS) {
    IOObjectRelease(service);
    return;
  }

  Row r;
  r["name"] = kDeviceNamePrefix + bsd_name;
  r["uuid"] = uuid;

  auto encrypted = getIOKitProperty(properties, kCoreStorageIsEncryptedKey_);
  if (encrypted.empty()) {
    r["encrypted"] = "0";
  } else {
    r["encrypted"] = encrypted;
    id_t uid;
    uuid_string_t uuid_string = {0};
    if (genUid(uid, uuid_string).ok()) {
      r["uid"] = BIGINT(uid);
      r["user_uuid"] = TEXT(uuid_string);
    }
  }
  r["type"] = (r.at("encrypted") == "1") ? kEncryptionType : std::string();

  results.push_back(r);
  CFRelease(properties);
  IOObjectRelease(service);
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  auto block_devices = SQL::selectAllFrom("block_devices");

  for (const auto& row : block_devices) {
    const auto bsd_name = row.at("name").substr(kDeviceNamePrefix.size());
    genFDEStatusForBSDName(bsd_name, row.at("uuid"), results);
  }

  return results;
}
}
}
