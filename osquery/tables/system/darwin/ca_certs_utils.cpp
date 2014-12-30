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
#include <boost/uuid/sha1.hpp>

#include "osquery/tables/system/darwin/ca_certs.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemKeychainPaths = {
    "/System/Library/Keychains", "/Library/Keychains",
};

const std::vector<std::string> kUserKeychainPaths = {
    "/Library/Keychains",
};

const std::map<std::string, Property> kCertificateProperties = {
    {"common_name", std::make_pair(kSecOIDCommonName, genCommonNameProperty)},
    {"not_valid_before",
     std::make_pair(kSecOIDX509V1ValidityNotBefore, stringFromCFNumber)},
    {"not_valid_after",
     std::make_pair(kSecOIDX509V1ValidityNotAfter, stringFromCFNumber)},
    {"key_algorithm",
     std::make_pair(kSecOIDX509V1SubjectPublicKeyAlgorithm,
                    genAlgorithmProperty)},
    {"key_usage", std::make_pair(kSecOIDKeyUsage, stringFromCFNumber)},
    {"subject_key_id",
     std::make_pair(kSecOIDSubjectKeyIdentifier, genKIDProperty)},
    {"authority_key_id",
     std::make_pair(kSecOIDAuthorityKeyIdentifier, genKIDProperty)},
};

std::string genKIDProperty(const CFDataRef& kid) {
  CFDataRef kid_data = NULL;
  CFDictionaryRef kid_dict = NULL;
  const char* kid_value = 0;

  // Find the key identifier data within the property mess.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)kid); i++) {
    kid_dict = (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)kid, i);
    kid_value =
        (const char*)CFDictionaryGetValue(kid_dict, kSecPropertyKeyValue);

    if (CFGetTypeID(kid_value) == CFDataGetTypeID()) {
      kid_data = (CFDataRef)kid_value;
      break;
    }
  }

  if (kid_data == NULL) {
    // No key identifier found.
    return "";
  }

  // Provide an ASCII-representation of the KID, similar to keychain.
  std::stringstream ascii_kid;
  int kid_byte;

  for (CFIndex i = 0; i < CFDataGetLength(kid_data) /* 20 */; i++) {
    kid_byte = (uint8_t)CFDataGetBytePtr(kid_data)[i];
    ascii_kid << std::setfill('0') << std::setw(2) << std::hex << kid_byte;
    // Then make it easy to read.
    if (i < CFDataGetLength(kid_data) - 1) {
      ascii_kid << "";
    }
  }

  return ascii_kid.str();
}

std::string genCommonNameProperty(const CFDataRef& ca) {
  CFDataRef ca_data = NULL;
  CFStringRef ca_string = NULL;

  // Find the key identifier data within the property mess.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)ca); i++) {
    ca_data = (CFDataRef)CFArrayGetValueAtIndex((CFArrayRef)ca, i);
    if (CFGetTypeID(ca_data) == CFStringGetTypeID()) {
      ca_string = (CFStringRef)ca_data;
      break;
    }
  }

  if (ca_string == NULL) {
    // Could not find a CFString reference within the common name array.
    return "";
  }

  // Access, then convert the CFString. CFStringGetCStringPtr is less-safe.
  return stringFromCFString(ca_string);
}

std::string genAlgorithmProperty(const CFDataRef& alg) {
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
  boost::uuids::detail::sha1 sha1;
  CFDataRef ca_data;

  // Access raw data, hash and release.
  ca_data = SecCertificateCopyData(ca);
  sha1.process_bytes(CFDataGetBytePtr(ca_data), CFDataGetLength(ca_data));
  CFRelease(ca_data);

  std::stringstream hash_output;
  unsigned int hash[5];

  // Return a hex-encoded friendly version of the 20byte-sha1.
  sha1.get_digest(hash);
  hash_output << std::hex << std::setfill('0') << std::setw(2);
  for (std::size_t i = 0; i < sizeof(hash) / sizeof(hash[0]); i++) {
    hash_output << hash[i];
  }

  return hash_output.str();
}

CFNumberRef CFNumberCreateCopy(const CFNumberRef& number) {
  // Easy way to get allow releasing numbers existing in arrays/dicts.
  // This follows Apple's guidance for "Create" APIs, caller controls memory.
  CFNumberRef copy;
  unsigned int value;

  if (!CFNumberGetValue(number, kCFNumberIntType, &value)) {
    return NULL;
  }

  copy = CFNumberCreate(NULL, kCFNumberIntType, &value);
  return copy;
}

CFDataRef CreatePropertyFromCertificate(const SecCertificateRef& cert,
                                        const CFTypeRef& oid) {
  CFDictionaryRef certificate_values;
  CFDictionaryRef property_values;
  CFDataRef property;
  CFMutableArrayRef keys;

  // Set the list of attributes.
  keys = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
  CFArrayAppendValue(keys, oid); // SecCertificateOIDs.h

  // Request dictionary of dictionaries (one for each attribute).
  certificate_values = SecCertificateCopyValues(cert, keys, NULL);
  CFRelease(keys);

  if (!CFDictionaryContainsKey(certificate_values, oid)) {
    // Certificate does not have the requested property.
    CFRelease(certificate_values);
    return NULL;
  }

  property_values =
      (CFDictionaryRef)CFDictionaryGetValue(certificate_values, oid);
  if (!CFDictionaryContainsKey(property_values, kSecPropertyKeyValue)) {
    // Odd, there was not value in the property result.
    CFRelease(certificate_values);
    return NULL;
  }

  // Create copy of the property value, which is an index to owned dict.
  property =
      (CFDataRef)CFDictionaryGetValue(property_values, kSecPropertyKeyValue);
  if (CFGetTypeID(property) == CFArrayGetTypeID()) {
    property = (CFDataRef)CFArrayCreateCopy(NULL, (CFArrayRef)property);
  } else if (CFGetTypeID(property) == CFNumberGetTypeID()) {
    property = (CFDataRef)CFNumberCreateCopy((CFNumberRef)property);
  } else {
    // LOG(ERROR) << "This property type is unknown...";
    property = NULL;
  }

  // Release and give the caller control of the property.
  CFRelease(certificate_values);
  return property;
}

bool CertificateIsCA(const SecCertificateRef& cert) {
  std::string expected_label = "Certificate Authority";
  std::string expected_value = "Yes";
  CFDataRef constraints;

  // Create copy of the basic constraints OID.
  constraints = CreatePropertyFromCertificate(cert, kSecOIDBasicConstraints);
  if (constraints == NULL) {
    return false;
  }

  // Must return an array of constraints.
  if (CFGetTypeID(constraints) != CFArrayGetTypeID()) {
    CFRelease(constraints);
    return false;
  }

  CFStringRef label, value;
  CFDictionaryRef constraint;
  bool isCA = false;

  // Find the expected value/label combination constraint.
  for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)constraints); i++) {
    constraint =
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)constraints, i);
    label = (CFStringRef)CFDictionaryGetValue(constraint, kSecPropertyKeyLabel);
    value = (CFStringRef)CFDictionaryGetValue(constraint, kSecPropertyKeyValue);

    if (expected_label.compare(stringFromCFString(label)) == 0 &&
        expected_value.compare(stringFromCFString(value)) == 0) {
      isCA = true;
      break;
    }
  }

  CFRelease(constraints);
  return isCA;
}
}
}
