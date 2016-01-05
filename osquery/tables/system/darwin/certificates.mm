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

#include "osquery/tables/system/darwin/keychain.h"

namespace osquery {
namespace tables {

void genCertificate(const SecCertificateRef& SecCert, QueryData& results) {
  Row r;

  auto der_encoded_data = SecCertificateCopyData(SecCert);
  if (der_encoded_data == nullptr) {
    return;
  }

  auto der_bytes = CFDataGetBytePtr(der_encoded_data);
  auto length = CFDataGetLength(der_encoded_data);
  auto cert = d2i_X509(nullptr, &der_bytes, length);

  if (cert == nullptr) {
    VLOG(1) << "Error decoding DER encoded certificate";
    CFRelease(der_encoded_data);
    return;
  }

  // Generate the common name and subject.
  // They are very similar OpenSSL API accessors so save some logic and
  // generate them using output parameters.
  genCommonName(cert, r["subject"], r["common_name"], r["issuer"]);
  // Same with algorithm strings.
  genAlgorithmProperties(
      cert, r["key_algorithm"], r["signing_algorithm"], r["key_size"]);

  // Most certificate field accessors return strings.
  r["not_valid_before"] = INTEGER(genEpoch(X509_get_notBefore(cert)));
  r["not_valid_after"] = INTEGER(genEpoch(X509_get_notAfter(cert)));

  // Get the keychain for the certificate.
  r["path"] = getKeychainPath((SecKeychainItemRef)SecCert);
  // Hash is not a certificate property, calculate using raw data.
  r["sha1"] = genSHA1ForCertificate(der_encoded_data);

  // X509_check_ca() populates key_usage, {authority,subject}_key_id
  // so it should be called before others.
  r["ca"] = (CertificateIsCA(cert)) ? INTEGER(1) : INTEGER(0);
  r["self_signed"] = (CertificateIsSelfSigned(cert)) ? INTEGER(1) : INTEGER(0);
  r["key_usage"] = genKeyUsage(cert->ex_kusage);
  r["authority_key_id"] =
      (cert->akid && cert->akid->keyid)
          ? genKIDProperty(cert->akid->keyid->data, cert->akid->keyid->length)
          : "";
  r["subject_key_id"] =
      (cert->skid) ? genKIDProperty(cert->skid->data, cert->skid->length) : "";

  results.push_back(r);
  X509_free(cert);
  CFRelease(der_encoded_data);
}

QueryData genCerts(QueryContext& context) {
  QueryData results;

  // Allow the caller to set an explicit certificate (keychain) search path.
  std::set<std::string> keychain_paths;
  if (context.constraints["path"].exists(EQUALS)) {
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
