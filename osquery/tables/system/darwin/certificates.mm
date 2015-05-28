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
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/tables/system/darwin/keychain.h"

namespace osquery {
namespace tables {

const std::map<std::string, CertProperty> kCertificateProperties = {
    {"common_name", {kSecOIDCommonName, genCommonNameProperty}},
    {"ca", {kSecOIDBasicConstraints, genCAProperty}},
    {"not_valid_before", {kSecOIDX509V1ValidityNotBefore, stringFromCFAbsoluteTime}},
    {"not_valid_after", {kSecOIDX509V1ValidityNotAfter, stringFromCFAbsoluteTime}},
    {"key_algorithm", {kSecOIDX509V1SubjectPublicKeyAlgorithm, genAlgProperty}},
    {"key_usage", {kSecOIDKeyUsage, stringFromCFNumber}},
    {"subject_key_id", {kSecOIDSubjectKeyIdentifier, genKIDProperty}},
    {"authority_key_id", {kSecOIDAuthorityKeyIdentifier, genKIDProperty}},
};

void genCertificate(const SecCertificateRef& cert, QueryData& results) {
  Row r;

  // Iterate through each selected certificate property.
  for (const auto &detail : kCertificateProperties) {
    auto property = CreatePropertyFromCertificate(cert, detail.second.type);
    if (property == nullptr) {
      r[detail.first] = "";
      continue;
    }
    // Each property may be stored differently, apply a generator function.
    r[detail.first] = detail.second.generate(property);
    CFRelease(property);
  }

  // Fix missing basic constraints to indicate CA:false.
  if (r["ca"] == "") {
    r["ca"] = "0";
  }

  // Get the keychain for the certificate.
  r["path"] = getKeychainPath((SecKeychainItemRef)cert);

  // Hash is not a certificate property, calculate using raw data.
  r["sha1"] = genSHA1ForCertificate(cert);
  results.push_back(r);
}

QueryData genCerts(QueryContext &context) {
  QueryData results;

  // Allow the caller to set an explicit certificate (keychain) search path.
  std::set<std::string> keychain_paths;
  if (context.constraints["path"].exists()) {
    keychain_paths = context.constraints["path"].getAll(EQUALS);
  } else {
    for (const auto& path : kSystemKeychainPaths) {
      keychain_paths.insert(path);
    }
    auto homes = osquery::getHomeDirectories();
    for (const auto& dir : homes) {
      for (const auto& keychains_dir : kUserKeychainPaths) {
        keychain_paths.insert((dir / keychains_dir).string());
      }
    }
  }

  // Keychains/certificate stores belonging to the OS.
  CFArrayRef certs = CreateKeychainItems(keychain_paths, kSecClassCertificate);
  // Must have returned an array of matching certificates.
  if (certs == nullptr) {
    VLOG(1) << "Could not find OS X Keychain";
    return {};
  } else if (CFGetTypeID(certs) != CFArrayGetTypeID()) {
    CFRelease(certs);
    return {};
  }

  // Evaluate the certificate data, check for CA in Basic constraints.
  auto certificate_count = CFArrayGetCount(certs);
  for (CFIndex i = 0; i < certificate_count; i++) {
    auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
    genCertificate(cert, results);
  }

  CFRelease(certs);
  return results;
}
}
}
