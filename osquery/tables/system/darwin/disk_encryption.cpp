/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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
  r["encrypted"] = (encrypted.empty()) ? "0" : encrypted;
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
