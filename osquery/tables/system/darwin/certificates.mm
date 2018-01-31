/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/tables/system/darwin/keychain.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_certificates_defs.hpp>

namespace osquery {
namespace tables {

void genCertificate(X509* cert, const std::string& path, QueryData& results) {
  Row r;

  // Generate the common name and subject.
  // They are very similar OpenSSL API accessors so save some logic and
  // generate them using output parameters.
  genCommonName(cert, r["subject"], r["common_name"], r["issuer"]);
  // Same with algorithm strings.
  genAlgorithmProperties(
      cert, r["key_algorithm"], r["signing_algorithm"], r["key_strength"]);

  // Most certificate field accessors return strings.
  r["not_valid_before"] = INTEGER(genEpoch(X509_get_notBefore(cert)));
  r["not_valid_after"] = INTEGER(genEpoch(X509_get_notAfter(cert)));

  // Get the keychain for the certificate.
  r["path"] = path;
  // Hash is not a certificate property, calculate using raw data.
  r["sha1"] = genSHA1ForCertificate(cert);

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
}

void genKeychainCertificate(const SecCertificateRef& SecCert,
                            QueryData& results) {
  auto der_encoded_data = SecCertificateCopyData(SecCert);
  if (der_encoded_data == nullptr) {
    return;
  }

  const unsigned char* der_bytes = CFDataGetBytePtr(der_encoded_data);
  auto length = CFDataGetLength(der_encoded_data);
  auto cert = d2i_X509(nullptr, &der_bytes, length);

  if (cert != nullptr) {
    auto path = getKeychainPath((SecKeychainItemRef)SecCert);
    genCertificate(cert, path, results);
    X509_free(cert);
  }

  CFRelease(der_encoded_data);
}

void genFileCertificate(const std::string& path, QueryData& results) {
  std::string content;
  auto s = readFile(path, content);
  if (!s.ok()) {
    return;
  }
  const unsigned char* bytes = (const unsigned char*)content.c_str();
  X509* cert = d2i_X509(nullptr, &bytes, content.size());

  if (cert != nullptr) {
    genCertificate(cert, path, results);
    X509_free(cert);
  } else {
    // If cert couldn't be read as DER, attempt
    // to read it as a PEM.
    BIO* bio = BIO_new_mem_buf((void*)bytes, content.size());

    // There might be multiple certificates in the PEM.
    while (PEM_read_bio_X509(bio, &cert, nullptr, nullptr) != nullptr) {
      genCertificate(cert, path, results);
      X509_free(cert);
      cert = nullptr;
    }

    BIO_free(bio);
  }
}

QueryData genCerts(QueryContext& context) {
  QueryData results;

  // Allow the caller to set both an explicit keychain search path
  // and certificate files on disk.
  std::set<std::string> keychain_paths;

  // Expand paths
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  if (!paths.empty()) {
    for (const auto& path : paths) {
      SecKeychainRef keychain = nullptr;
      SecKeychainStatus keychain_status;
      auto status = SecKeychainOpen(path.c_str(), &keychain);
      if (status != errSecSuccess || keychain == nullptr ||
          SecKeychainGetStatus(keychain, &keychain_status) != errSecSuccess) {
        if (keychain != nullptr) {
          CFRelease(keychain);
        }
        genFileCertificate(path, results);
      } else {
        keychain_paths.insert(path);
        CFRelease(keychain);
      }
    }
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
  if (certs != nullptr) {
    if (CFGetTypeID(certs) == CFArrayGetTypeID()) {
      auto certificate_count = CFArrayGetCount(certs);
      for (CFIndex i = 0; i < certificate_count; i++) {
        auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
        genKeychainCertificate(cert, results);
      }
    }
    CFRelease(certs);
  }

  return results;
}
}
}
