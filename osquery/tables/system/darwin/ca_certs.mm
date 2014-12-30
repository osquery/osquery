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
//#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/darwin/ca_certs.h"

namespace osquery {
namespace tables {

bool genOSXAuthorities(CFArrayRef &reference) {
  CFArrayRef keychain_certs;
  CFMutableDictionaryRef query;
  OSStatus status = errSecSuccess;

  query = CFDictionaryCreateMutable(NULL,
                                    0,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassCertificate);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  // This can be added to restrict results to x509v3
  // CFDictionaryAddValue(query, kSecAttrCertificateType, 0x03);
  CFDictionaryAddValue(query, kSecAttrCanVerify, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);

  status = SecItemCopyMatching(query, (CFTypeRef *)&keychain_certs);
  CFRelease(query);

  if (status != errSecSuccess) {
    reference = NULL;
    return false;
  }

  // Limit certificates to authorities (kSecOIDBasicConstraints).
  CFMutableArrayRef authorities;
  SecCertificateRef cert;

  // Store just the authority certificates.
  authorities = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

  // For each certificate returned from the search, get the constraints prop.
  for (CFIndex i = 0; i < CFArrayGetCount(keychain_certs); i++) {
    cert = (SecCertificateRef)CFArrayGetValueAtIndex(keychain_certs, i);
    if (CertificateIsCA(cert)) {
      CFArrayAppendValue(authorities, cert);
    }
  }

  reference = (CFArrayRef)authorities;
  CFRelease(keychain_certs);
  return (status == errSecSuccess);
}

QueryData genCerts(QueryContext &context) {
  QueryData results;
  CFArrayRef authorities = NULL;
  // Keychains/certificate stores belonging to the OS.
  if (!genOSXAuthorities(authorities)) {
    // LOG(ERROR) << "Could not find OSX Keychain Certificate Authorities.";
    return results;
  }

  // Must have returned an array of matching certificates.
  if (CFGetTypeID(authorities) != CFArrayGetTypeID()) {
    // LOG(ERROR) << "Unknown certificate authorities type.";
    return results;
  }

  // Evaluate the certificate data, check for CA in Basic constraints.
  unsigned int certificate_count = 0;
  SecCertificateRef ca = NULL;
  CFDataRef property = NULL;

  certificate_count = CFArrayGetCount((CFArrayRef)authorities);
  for (CFIndex i = 0; i < certificate_count; i++) {
    Row r;
    ca = (SecCertificateRef)CFArrayGetValueAtIndex(authorities, i);

    // Iterate through each selected certificate property.
    for (const auto &property_iterator : kCertificateProperties) {
      property =
          CreatePropertyFromCertificate(ca, property_iterator.second.first);
      if (property == NULL) {
        continue;
      }
      // Each property may be stored differently, apply a generator function.
      r[property_iterator.first] = property_iterator.second.second(property);
      CFRelease(property);
    }

    r["sha1"] = genSHA1ForCertificate(ca);
    results.push_back(r);
  }

  CFRelease(authorities);
  return results;
}
}
}
