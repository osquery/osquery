/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <iomanip>

#include <boost/lexical_cast.hpp>

#include <osquery/filesystem.h>
#include <osquery/hash.h>

#include "osquery/tables/system/darwin/keychain.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemKeychainPaths = {
    "/System/Library/Keychains", "/Library/Keychains",
};

const std::vector<std::string> kUserKeychainPaths = {
    "/Library/Keychains",
};

void genKeychains(const std::string& path, CFMutableArrayRef& keychains) {
  std::vector<std::string> paths;

  // Support both a directory and explicit path search.
  if (isDirectory(path).ok()) {
    // Try to list every file in the given keychain search path.
    if (!listFilesInDirectory(path, paths).ok()) {
      return;
    }
  } else {
    // The explicit path search comes from a query predicate.
    paths.push_back(path);
  }

  for (const auto& keychain_path : paths) {
    SecKeychainRef keychain = nullptr;
    auto status = SecKeychainOpen(keychain_path.c_str(), &keychain);
    if (status == 0 && keychain != nullptr) {
      CFArrayAppendValue(keychains, keychain);
    }
  }
}

std::string getKeychainPath(const SecKeychainItemRef& item) {
  SecKeychainRef keychain = nullptr;
  std::string path;
  auto status = SecKeychainItemCopyKeychain(item, &keychain);
  if (keychain == nullptr || status != errSecSuccess) {
    // Unhandled error, cannot get the keychain reference from certificate.
    return path;
  }

  UInt32 path_size = 1024;
  char keychain_path[1024] = {0};
  status = SecKeychainGetPath(keychain, &path_size, keychain_path);
  if (status != errSecSuccess || (path_size > 0 && keychain_path[0] != 0)) {
    path = std::string(keychain_path);
  }

  CFRelease(keychain);
  return path;
}

std::string genKIDProperty(const CFDataRef& kid) {
  CFDataRef kid_data = nullptr;
  CFDictionaryRef kid_dict = nullptr;

  // Find the key identifier data within the property mess.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)kid); i++) {
    kid_dict = (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)kid, i);
    auto kid_value =
        (const char*)CFDictionaryGetValue(kid_dict, kSecPropertyKeyValue);

    if (CFGetTypeID(kid_value) == CFDataGetTypeID()) {
      kid_data = (CFDataRef)kid_value;
      break;
    }
  }

  if (kid_data == nullptr) {
    // No key identifier found.
    return "";
  }

  // Provide an ASCII-representation of the KID, similar to keychain.
  std::stringstream ascii_kid;
  for (CFIndex i = 0; i < CFDataGetLength(kid_data); i++) {
    int kid_byte = (uint8_t)CFDataGetBytePtr(kid_data)[i];
    ascii_kid << std::setfill('0') << std::setw(2) << std::hex << kid_byte;
    // Then make it easy to read.
    if (i < CFDataGetLength(kid_data) - 1) {
      ascii_kid << "";
    }
  }

  return ascii_kid.str();
}

std::string genCommonNameProperty(const CFDataRef& ca) {
  CFDataRef ca_data = nullptr;
  CFStringRef ca_string = nullptr;

  // Find the key identifier data within the property mess.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)ca); i++) {
    ca_data = (CFDataRef)CFArrayGetValueAtIndex((CFArrayRef)ca, i);
    if (CFGetTypeID(ca_data) == CFStringGetTypeID()) {
      ca_string = (CFStringRef)ca_data;
      break;
    }
  }

  if (ca_string == nullptr) {
    // Could not find a CFString reference within the common name array.
    return "";
  }

  // Access, then convert the CFString. CFStringGetCStringPtr is less-safe.
  return stringFromCFString(ca_string);
}

std::string genAlgProperty(const CFDataRef& alg) {
  std::string expected_label = "Algorithm";
  CFStringRef label, value;
  CFDictionaryRef alg_item;

  // Find the key identifier data within the property mess.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)alg); i++) {
    alg_item = (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)alg, i);
    label = (CFStringRef)CFDictionaryGetValue(alg_item, kSecPropertyKeyLabel);
    value = (CFStringRef)CFDictionaryGetValue(alg_item, kSecPropertyKeyValue);

    if (expected_label.compare(stringFromCFString(label)) == 0) {
      return stringFromCFString(value);
    }
  }

  // Unknown algorithm OID.
  return "";
}

std::string genSHA1ForCertificate(const SecCertificateRef& ca) {
  CFDataRef ca_data;

  // Access raw data, hash and release.
  ca_data = SecCertificateCopyData(ca);
  auto digest = hashFromBuffer(
      HASH_TYPE_SHA1, CFDataGetBytePtr(ca_data), CFDataGetLength(ca_data));
  CFRelease(ca_data);
  return digest;
}

CFNumberRef CFNumberCreateCopy(const CFNumberRef& number) {
  // Easy way to get allow releasing numbers existing in arrays/dicts.
  // This follows Apple's guidance for "Create" APIs, caller controls memory.
  CFNumberRef copy;
  unsigned int value;

  if (!CFNumberGetValue(number, kCFNumberIntType, &value)) {
    return nullptr;
  }

  copy = CFNumberCreate(nullptr, kCFNumberIntType, &value);
  return copy;
}

CFDataRef CreatePropertyFromCertificate(const SecCertificateRef& cert,
                                        const CFTypeRef& oid) {
  // Set the list of attributes.
  auto keys = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
  CFArrayAppendValue(keys, oid); // SecCertificateOIDs.h

  // Request dictionary of dictionaries (one for each attribute).
  auto certificate_values = SecCertificateCopyValues(cert, keys, nullptr);
  CFRelease(keys);

  if (!CFDictionaryContainsKey(certificate_values, oid)) {
    // Certificate does not have the requested property.
    CFRelease(certificate_values);
    return nullptr;
  }

  auto values = (CFDictionaryRef)CFDictionaryGetValue(certificate_values, oid);
  if (!CFDictionaryContainsKey(values, kSecPropertyKeyValue)) {
    // Odd, there was not value in the property result.
    CFRelease(certificate_values);
    return nullptr;
  }

  // Create copy of the property value, which is an index to owned dict.
  auto property = (CFDataRef)CFDictionaryGetValue(values, kSecPropertyKeyValue);
  if (CFGetTypeID(property) == CFArrayGetTypeID()) {
    property = (CFDataRef)CFArrayCreateCopy(nullptr, (CFArrayRef)property);
  } else if (CFGetTypeID(property) == CFNumberGetTypeID()) {
    property = (CFDataRef)CFNumberCreateCopy((CFNumberRef)property);
  } else {
    property = nullptr;
  }

  // Release and give the caller control of the property.
  CFRelease(certificate_values);
  return property;
}

CFArrayRef CreateKeychainItems(const std::set<std::string>& paths,
                               const CFTypeRef& item_type) {
  auto keychains = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
  for (const auto& path : paths) {
    genKeychains(path, keychains);
  }

  CFMutableDictionaryRef query;
  query = CFDictionaryCreateMutable(nullptr,
                                    0,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, item_type);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  // This can be added to restrict results to x509v3
  // CFDictionaryAddValue(query, kSecAttrCertificateType, 0x03);
  CFDictionaryAddValue(query, kSecMatchSearchList, keychains);
  CFDictionaryAddValue(query, kSecAttrCanVerify, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);

  CFArrayRef keychain_certs;
  auto status = SecItemCopyMatching(query, (CFTypeRef*)&keychain_certs);
  CFRelease(query);

  if (status != errSecSuccess) {
    return nullptr;
  }

  // Release each keychain search path.
  CFRelease(keychains);

  return keychain_certs;
}

std::string genCAProperty(const CFDataRef& constraints) {
  // Must return an array of constraints.
  if (CFGetTypeID(constraints) != CFArrayGetTypeID()) {
    return "-1";
  }

  std::string expected_label = "Certificate Authority";
  std::string expected_value = "Yes";

  CFStringRef label, value;
  CFDictionaryRef constraint;
  // Find the expected value/label combination constraint.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)constraints); i++) {
    constraint =
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)constraints, i);
    label = (CFStringRef)CFDictionaryGetValue(constraint, kSecPropertyKeyLabel);
    value = (CFStringRef)CFDictionaryGetValue(constraint, kSecPropertyKeyValue);

    if (expected_label.compare(stringFromCFString(label)) == 0 &&
        expected_value.compare(stringFromCFString(value)) == 0) {
      return "1";
    }
  }

  return "0";
}

std::set<std::string> getKeychainPaths() {
  std::set<std::string> keychain_paths;

  for (const auto& path : kSystemKeychainPaths) {
    keychain_paths.insert(path);
  }

  auto homes = getHomeDirectories();
  for (const auto& dir : homes) {
    for (const auto& keychains_dir : kUserKeychainPaths) {
      keychain_paths.insert((dir / keychains_dir).string());
    }
  }

  return keychain_paths;
}
}
}
