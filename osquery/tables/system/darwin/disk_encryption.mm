/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <Foundation/Foundation.h>
#include <DiskArbitration/DiskArbitration.h>

#include <membership.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/sql.h>

#include "osquery/events/darwin/iokit.h"
#include "osquery/events/darwin/diskarbitration.h"

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

/// Expect all device names to include a /dev path prefix.
const std::string kDeviceNamePrefix = "/dev/";

const std::set<std::string> kHardcodedDiskUUIDs = {
  "EBC6C064-0000-11AA-AA11-00306543ECA",
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
    auto bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/DiskManagement.framework"),
      kCFURLPOSIXPathStyle,
      true);
    if (bundle_url == nullptr) {
      LOG(ERROR) << "parsing bundle URL";
      return;
    }

    auto bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
    CFRelease(bundle_url);
    if (bundle == nullptr) {
      LOG(ERROR) << "opening bundle";
      return;
   }

    CFBundleLoadExecutable(bundle);

    DASessionRef session = DASessionCreate(kCFAllocatorDefault);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    // DMManager *man = [DMManager sharedManager]
    id cls = NSClassFromString(@"DMManager");
    SEL sls = NSSelectorFromString(@"sharedManager");
    id man = [cls performSelector:sls];

    // DMAPFS * apfs = [[DMAPFS alloc] initWithManager:man];
    cls = NSClassFromString(@"DMAPFS");
    sls = NSSelectorFromString(@"alloc");
    id apfs = [cls performSelector:sls];
    sls = NSSelectorFromString(@"initWithManager:");
    [apfs performSelector:sls withObject:man];

#pragma clang diagnostic pop

    DADiskRef targetVol = DADiskCreateFromBSDName(nullptr, session, r["name"].c_str());

    // The following is an NSInvocation form of this objc line:
    // err = [apfs isEncryptedVolume:targetVol encrypted:&isEncrypted];
    char *typeEncodings;
        asprintf(&typeEncodings, "%s%s%s%s%s",
                 @encode(int),     // return
                 @encode(id),       // self
                 @encode(SEL),      // _cmd
                 @encode(DADiskRef),
                 @encode(char*)
                 );
    NSMethodSignature *signature = [NSMethodSignature signatureWithObjCTypes: typeEncodings];
    free(typeEncodings);

    char isEncrypted = 1;
    char *isEncryptedPtr = &isEncrypted;
    int err = 0;

    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:signature];
    [inv setSelector:@selector(isEncryptedVolume:encrypted:)];
    [inv setReturnValue:&err];
    [inv setArgument:&targetVol atIndex:2];
    [inv setArgument:&isEncryptedPtr atIndex:3];
    [inv invokeWithTarget:apfs];

        asprintf(&typeEncodings, "%s%s%s%s%s",
                 @encode(int),     // return
                 @encode(id),       // self
                 @encode(SEL),      // _cmd
                 @encode(DADiskRef),
                 @encode(void*)
                 );
    signature = [NSMethodSignature signatureWithObjCTypes: typeEncodings];
    free(typeEncodings);

    NSArray *cryptoUsers;
    void *cryptoUsersPtr = &cryptoUsers;
    inv = [NSInvocation invocationWithMethodSignature:signature];
    [inv setSelector:@selector(cryptoUsersForVolume:users:)];
    [inv setReturnValue:&err];
    [inv setArgument:&targetVol atIndex:2];
    [inv setArgument:&cryptoUsersPtr atIndex:3];
    [inv invokeWithTarget:apfs];

    CFRelease(session);
    CFRelease(targetVol);
    CFRelease((__bridge CFTypeRef)apfs);

    if (cryptoUsers != nullptr) {
      @autoreleasepool {
        for (NSString *userUUID in cryptoUsers) {
          std::string uuidStr = std::string([userUUID UTF8String]);
          if (kHardcodedDiskUUIDs.count(uuidStr) == 0) {
            QueryData rows = SQL::selectAllFrom("users", "uuid", EQUALS, "foo");
            for (auto &row : rows) {
              if (row["uuid"] == uuidStr) {
                r["user_uuid"] = row["uuid"];
                r["uid"] = row["uid"];
              }
            }
          }
        }
      }
    }

    r["encrypted"] = isEncrypted ? "1" : "0";
    r["type"] = isEncrypted ? "APFS Encryption" : "";

    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  } else {
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
  }

  results.push_back(r);
  CFRelease(properties);
  IOObjectRelease(service);
}

bool isAPFS(const QueryData& result) {
  if (result.empty()) {
    return false;
  }

  if (result[0].at("type") == kAPFSFileSystem) {
    return true;
  }
  return false;
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  auto block_devices = SQL::selectAllFrom("block_devices");

  for (const auto& row : block_devices) {
    const auto bsd_name = row.at("name").substr(kDeviceNamePrefix.size());
    auto mount = SQL::selectAllFrom("mounts", "device", EQUALS, bsd_name);
    genFDEStatusForBSDName(bsd_name, row.at("uuid"), isAPFS(mount), results);
  }

  return results;
}
}
}
