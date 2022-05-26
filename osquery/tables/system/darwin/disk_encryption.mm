/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <DiskArbitration/DiskArbitration.h>
#include <Foundation/Foundation.h>

#include <functional>

#include <membership.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/events/darwin/diskarbitration.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

/**
 * @brief The block algorithm supported by FileValue2.
 *
 * AES-XTS is the only block algorithm supported.
 * See: https://opensource.apple.com/source/xnu/xnu-2782.1.97/\
 *   libkern/crypto/corecrypto_aesxts.c
 */
const std::string kEncryptionType = "AES-XTS";
const std::string kAPFSFileSystem = "apfs";
const std::string kFileVaultStatusOn = "on";
const std::string kFileVaultStatusOff = "off";
const std::string kFileVaultStatusUnknown = "unknown";
const std::string kEncryptionStatusEncrypted = "encrypted";
const std::string kEncryptionStatusUndefined = "undefined";
const std::string kEncryptionStatusNotEncrypted = "not encrypted";

/// Expect all device names to include a /dev path prefix.
const std::string kDeviceNamePrefix = "/dev/";

const std::set<std::string> kHardcodedDiskUUIDs = {
    "EBC6C064-0000-11AA-AA11-00306543ECAC",
    "64C0C6EB-0000-11AA-AA11-00306543ECAC",
    "C064EBC6-0000-11AA-AA11-00306543ECAC",
    "ec1c2ad9-b618-4ed6-bd8d-50f361c27507",
    "2fa31400-baff-4de7-ae2a-c3aa6e1fd340",
};

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
      CFRelease(properties);
      return Status(1, "Unexpected data type for unlock ident");
    }
    uuid = CFDataCreateCopy(kCFAllocatorDefault, (CFDataRef)unlock_ident);
    if (uuid == nullptr) {
      CFRelease(properties);
      return Status(1, "Could not get UUID");
    }
    CFRelease(properties);
    return Status(0, "ok");
  }

  CFRelease(properties);
  return Status(1, "Could not get unlock ident");
}

Status genUid(id_t& uid, uuid_string_t& uuid_str) {
  CFDataRef uuid = nullptr;
  if (!genUnlockIdent(uuid).ok()) {
    if (uuid != nullptr) {
      CFRelease(uuid);
    }
    return Status(1, "Could not get unlock ident");
  }

  CFDataGetBytes(uuid, CFRangeMake(0, CFDataGetLength(uuid)), (UInt8*)uuid_str);
  if (uuid != nullptr) {
    CFRelease(uuid);
  }

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

void genFDEStatusForAPFS(Row& r) {
  // Set encryption_status as undefined at start
  // and change it to encrypted | not encrypted in future
  r["encryption_status"] = kEncryptionStatusUndefined;
  r["filevault_status"] = kFileVaultStatusUnknown;

  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks.
  auto bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/DiskManagement.framework"),
      kCFURLPOSIXPathStyle,
      true);
  if (bundle_url == nullptr) {
    LOG(ERROR) << "Error parsing DiskManagement bundle URL";
    return;
  }

  auto bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    LOG(ERROR) << "Error opening DiskManagement bundle";
    return;
  }

  CFBundleLoadExecutable(bundle);

  std::function<void()> cleanup = [&]() {
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

  DASessionRef session = DASessionCreate(kCFAllocatorDefault);
  if (session == nullptr) {
    LOG(ERROR) << "Error creating DiskArbitration session";
    cleanup();
    return;
  }
  cleanup = [&]() {
    CFRelease(session);
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
  // DMManager *man = [DMManager sharedManager]
  id cls = NSClassFromString(@"DMManager");
  if (cls == nullptr) {
    LOG(ERROR) << "Could not load DMManager class";
    cleanup();
    return;
  }
  SEL sel = @selector(sharedManager);
  if (![cls respondsToSelector:sel]) {
    LOG(ERROR) << "DMManager does not respond to sharedManager selector";
    cleanup();
    return;
  }
  id man = [cls performSelector:sel];
  if (man == nullptr) {
    LOG(ERROR) << "[DMManager sharedManager] returned null";
    cleanup();
    return;
  }

  // DMAPFS * apfs = [[DMAPFS alloc] initWithManager:man];
  cls = NSClassFromString(@"DMAPFS");
  if (cls == nullptr) {
    LOG(ERROR) << "Could not load DMAPFS class";
    cleanup();
    return;
  }
  sel = @selector(alloc);
  if (![cls respondsToSelector:sel]) {
    LOG(ERROR) << "DMAPFS does not respond to alloc selector";
    cleanup();
    return;
  }
  id apfs = [cls performSelector:sel];
  if (apfs == nullptr) {
    LOG(ERROR) << "Could not allocate DMAPFS object";
    cleanup();
    return;
  }

  sel = @selector(initWithManager:);
  if (![apfs respondsToSelector:sel]) {
    LOG(ERROR) << "DMAPFS does not respond to initWithManager: selector";
    cleanup();
    return;
  }
  [apfs performSelector:sel withObject:man];

  cleanup = [&]() {
    CFRelease((__bridge CFTypeRef)apfs);
    CFRelease(session);
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

#pragma clang diagnostic pop

  DADiskRef targetVol =
      DADiskCreateFromBSDName(nullptr, session, r["name"].c_str());
  if (targetVol == nullptr) {
    LOG(ERROR) << "Error creating target volume from BSD name";
    cleanup();
    return;
  }
  cleanup = [&]() {
    CFRelease(targetVol);
    CFRelease((__bridge CFTypeRef)apfs);
    CFRelease(session);
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

  int err = 0;

  char isEncrypted = 0;

  // err = [apfs isEncryptedVolume:targetVol encrypted:&isEncrypted];
  @try {
    SEL selector = @selector(isEncryptedVolume:encrypted:);
    IMP methodIMP = [apfs methodForSelector:selector];
    if (methodIMP == nullptr) {
      LOG(ERROR) << "Failed to get method IMP for isEncryptedVolume:encrypted:";
      cleanup();
      return;
    }
    int (*function)(id, SEL, DADiskRef, char*) =
        (int (*)(id, SEL, DADiskRef, char*))(methodIMP);
    err = function(apfs, selector, targetVol, &isEncrypted);
  } @catch (NSException* exception) {
    LOG(ERROR) << "isEncryptedVolume:encrypted: threw exception "
               << exception.name;
    cleanup();
    return;
  }
  if (err != 0) {
    // This is expected behaviour on some configurations
    // We can't handle error here so just log
    LOG(INFO) << "Error calling isEncryptedVolume:encrypted:";
    // For backward compatibility reasons mark disk as
    // not encrypted
    r["encrypted"] = "0";
    cleanup();
    return;
  }

  char isFileVaultEnabled = 0;

  // err = [apfs isFileVaultEnabled:targetVol enabled:&isFileVaultEnabled];
  @try {
    SEL selector = @selector(isFileVaultEnabled:enabled:);
    IMP methodIMP = [apfs methodForSelector:selector];
    if (methodIMP == nullptr) {
      LOG(ERROR) << "Failed to get method IMP for isFileVaultEnabled:enabled:";
      cleanup();
      return;
    }
    int (*function)(id, SEL, DADiskRef, char*) =
        (int (*)(id, SEL, DADiskRef, char*))(methodIMP);
    err = function(apfs, selector, targetVol, &isFileVaultEnabled);
  } @catch (NSException* exception) {
    LOG(ERROR) << "isFileVaultEnabled:enabled: threw exception "
               << exception.name;
    cleanup();
    return;
  }
  if (err != 0) {
    // This is expected behaviour on some configurations
    // We can't handle error here so just log
    LOG(INFO) << "Error calling isFileVaultEnabled:enabled:";
    cleanup();
    return;
  }

  // err = [apfs cryptoUsersForVolume:targetVol users:&cryptoUsers];
  NSArray* cryptoUsers = nullptr;
  @try {
    SEL selector = @selector(cryptoUsersForVolume:users:);
    IMP methodIMP = [apfs methodForSelector:selector];
    if (methodIMP == nullptr) {
      LOG(ERROR) << "Failed to get method IMP for cryptoUsersForVolume:users:";
      cleanup();
      return;
    }
    int (*function)(id, SEL, DADiskRef, id*) =
        (int (*)(id, SEL, DADiskRef, id __autoreleasing*))(methodIMP);
    err = function(apfs, selector, targetVol, &cryptoUsers);
  } @catch (NSException* exception) {
    LOG(ERROR) << "cryptoUsersForVolume:users: threw exception "
               << exception.name;
    cleanup();
    return;
  }

  // We can perform this cleanup before analyzing the results of the calls.
  cleanup();

  if (err != 0) {
    LOG(ERROR) << "Error calling cryptoUsersForVolume:users: ";
    return;
  }

  if (cryptoUsers != nullptr) {
    for (id arrObj in cryptoUsers) {
      if (![arrObj isKindOfClass:[NSString class]]) {
        continue;
      }

      const char* cStr = [(NSString*)arrObj UTF8String];
      if (cStr == nullptr) {
        continue;
      }
      std::string uuidStr(cStr);

      if (kHardcodedDiskUUIDs.count(uuidStr) == 0) {
        QueryData rows = SQL::selectAllFrom("users");
        for (const auto& row : rows) {
          if (row.count("uuid") > 0 && row.at("uuid") == uuidStr) {
            r["user_uuid"] = row.at("uuid");
            r["uid"] = row.count("uid") > 0 ? row.at("uid") : "";
          }
        }
      }
    }
  }

  r["encryption_status"] =
      isEncrypted ? kEncryptionStatusEncrypted : kEncryptionStatusNotEncrypted;

  r["filevault_status"] =
      isFileVaultEnabled ? kFileVaultStatusOn : kFileVaultStatusOff;

  r["encrypted"] = isEncrypted ? "1" : "0";
  r["type"] = isEncrypted ? "APFS Encryption" : "";
}

void genFDEStatusForBSDName(const std::string& bsd_name,
                            const std::string& uuid,
                            bool isAPFS,
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

  if (isAPFS) {
    genFDEStatusForAPFS(r);
  } else {
    auto encrypted = getIOKitProperty(properties, kCoreStorageIsEncryptedKey_);
    if (encrypted.empty()) {
      r["encryption_status"] = kEncryptionStatusUndefined;
      r["filevault_status"] = kFileVaultStatusUnknown;
      r["encrypted"] = "0";
    } else {
      r["encrypted"] = encrypted;

      r["encryption_status"] = encrypted == "1" ? kEncryptionStatusEncrypted
                                                : kEncryptionStatusNotEncrypted;

      // On non-APFS drives we consider encryption and filevault to mean the
      // same thing as it makes the UX of querying the table for the most
      // common case (finding macs without Filevault enabled)
      r["filevault_status"] =
          encrypted == "1" ? kFileVaultStatusOn : kFileVaultStatusOff;

      id_t uid;
      uuid_string_t uuid_string = {0};
      if (genUid(uid, uuid_string).ok()) {
        r["uid"] = BIGINT(uid);
        r["user_uuid"] = TEXT(uuid_string);
      }
    }
    r["type"] = (r.at("encrypted") == "1") ? kEncryptionType : std::string();
  }

  results.push_back(r);
  CFRelease(properties);
  IOObjectRelease(service);
}

bool isAPFS(const std::unordered_map<std::string, bool>& lookup,
            const std::string& key) {
  auto it = lookup.find(key);

  if (it == lookup.end()) {
    return false;
  }

  // We only need to check the first mount -- the rest should be the same.
  return it->second;
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  // For a given device, we need to tell if it's an apfs. We do this
  // by looking at the type column from the mounts table. Fetch this
  // here, so don't have to keep refetching.
  std::unordered_map<std::string, bool> deviceIsAPFS;
  for (const auto& row : SQL::selectAllFrom("mounts")) {
    std::string device, type;
    for (const auto& [k, v] : row) {
      if (k == "device") {
        device = v;
      } else if (k == "type") {
        type = v;
      }
    }
    if (!device.empty() && !type.empty()) {
      deviceIsAPFS[device] = type == kAPFSFileSystem;
    }
  }

  bool runSelectAll(true);
  QueryData block_devices;

  if (auto constraint_it = context.constraints.find("name");
      constraint_it != context.constraints.end()) {
    const auto& constraints = constraint_it->second;
    for (const auto& name : constraints.getAll(EQUALS)) {
      runSelectAll = false;

      auto data = SQL::selectAllFrom("block_devices", "name", EQUALS, name);
      for (const auto& row : data) {
        block_devices.push_back(row);
      }
    }
  }

  if (runSelectAll) {
    block_devices = SQL::selectAllFrom("block_devices");
  }

  for (const auto& row : block_devices) {
    auto name = row.at("name");
    @autoreleasepool {
      const auto bsd_name = name.substr(kDeviceNamePrefix.size());
      genFDEStatusForBSDName(
          bsd_name, row.at("uuid"), isAPFS(deviceIsAPFS, name), results);
    }
  }
  return results;
}
}
}
