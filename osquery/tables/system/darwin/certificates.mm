/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/tables/system/posix/openssl_utils.h>

namespace osquery {
namespace tables {

void genCertificate(X509* cert, const std::string& path, QueryData& results) {
  Row r;

  auto opt_issuer_name = getCertificateIssuerName(cert, true);
  r["issuer"] = SQL_TEXT(opt_issuer_name.value_or(""));

  opt_issuer_name = getCertificateIssuerName(cert, false);
  r["issuer2"] = SQL_TEXT(opt_issuer_name.value_or(""));

  auto opt_subject_name = getCertificateSubjectName(cert, true);
  r["subject"] = SQL_TEXT(opt_subject_name.value_or(""));

  opt_subject_name = getCertificateSubjectName(cert, false);
  r["subject2"] = SQL_TEXT(opt_subject_name.value_or(""));

  auto opt_common_name = getCertificateCommonName(cert);
  r["common_name"] = SQL_TEXT(opt_common_name.value_or(""));

  auto opt_signing_algorithm = getCertificateSigningAlgorithm(cert);
  r["signing_algorithm"] = SQL_TEXT(opt_signing_algorithm.value_or(""));

  auto opt_key_algorithm = getCertificateKeyAlgorithm(cert);
  r["key_algorithm"] = SQL_TEXT(opt_key_algorithm.value_or(""));

  auto opt_key_strength = getCertificateKeyStregth(cert);
  r["key_strength"] = SQL_TEXT(opt_key_strength.value_or(""));

  auto opt_not_valid_before = getCertificateNotValidBefore(cert);
  r["not_valid_before"] = INTEGER(opt_not_valid_before.value_or(0));

  auto opt_not_valid_after = getCertificateNotValidAfter(cert);
  r["not_valid_after"] = INTEGER(opt_not_valid_after.value_or(0));

  // Get the keychain for the certificate.
  r["path"] = path;
  // Hash is not a certificate property, calculate using raw data.
  auto opt_digest = generateCertificateSHA1Digest(cert);
  r["sha1"] = SQL_TEXT(opt_digest.value_or(""));

  // X509_check_ca() populates key_usage, {authority,subject}_key_id
  // so it should be called before others.
  bool is_ca{};
  bool is_self_signed{};
  getCertificateAttributes(cert, is_ca, is_self_signed);

  r["ca"] = is_ca ? INTEGER(1) : INTEGER(0);
  r["self_signed"] = is_self_signed ? INTEGER(1) : INTEGER(0);

  auto opt_cert_key_usage = getCertificateKeyUsage(cert);
  r["key_usage"] = opt_cert_key_usage.value_or("");

  auto opt_authority_key_id = getCertificateAuthorityKeyID(cert);
  r["authority_key_id"] = SQL_TEXT(opt_authority_key_id.value_or(""));

  auto opt_subject_key_id = getCertificateSubjectKeyID(cert);
  r["subject_key_id"] = SQL_TEXT(opt_subject_key_id.value_or(""));

  auto opt_cert_serial_number = getCertificateSerialNumber(cert);
  r["serial"] = SQL_TEXT(opt_cert_serial_number.value_or(""));

  results.push_back(r);
}

void genKeychainCertificate(const SecCertificateRef& SecCert,
                            QueryData& results,
                            const KeychainMap& keychain_map) {
  auto der_encoded_data = SecCertificateCopyData(SecCert);
  if (der_encoded_data == nullptr) {
    return;
  }

  const unsigned char* der_bytes = CFDataGetBytePtr(der_encoded_data);
  auto length = CFDataGetLength(der_encoded_data);
  auto cert = d2i_X509(nullptr, &der_bytes, length);

  if (cert != nullptr) {
    auto path = getKeychainPath((SecKeychainItemRef)SecCert);
    auto dest = boost::filesystem::path(path);
    auto it = keychain_map.temp_to_actual.find(dest);
    // TODO: Add error handling/logging here.
    genCertificate(cert, it->second.string(), results);
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

  // All files will be copied to a temp directory before being processed.
  // This attempts to fix the keychain corruption seen in https://github.com/osquery/osquery/issues/7780
  KeychainMap keychain_map;
  // Base temp directory that we will need to delete.
  keychain_map.temp_base = boost::filesystem::canonical(boost::filesystem::temp_directory_path()) / boost::filesystem::unique_path();

  @autoreleasepool {
    if (!paths.empty()) {
      for (const auto& path : paths) {
        boost::filesystem::path source(path);
        if (is_regular_file(source) && keychain_map.actual_to_temp.count(source) == 0) {
          // Make a copy. Using a unique subdirectory to prevent filename conflicts.
          auto temp_dir = keychain_map.temp_base / boost::filesystem::unique_path();
          boost::filesystem::create_directories(temp_dir);
          boost::filesystem::path dest = temp_dir / source.filename();
          boost::filesystem::copy_file(source, dest);
          keychain_map.Insert(source, dest);

          SecKeychainRef keychain = nullptr;
          SecKeychainStatus keychain_status;
          auto status = SecKeychainOpen(dest.c_str(), &keychain);
          if (status != errSecSuccess || keychain == nullptr ||
              SecKeychainGetStatus(keychain, &keychain_status) != errSecSuccess) {
            if (keychain != nullptr) {
              CFRelease(keychain);
            }
            // Using the actual path here instead of temp path.
            genFileCertificate(source.string(), results);
          } else {
            keychain_paths.insert(path);
            CFRelease(keychain);
          }
        }
      }
    } else {
      keychain_paths = getKeychainPaths();
    }

    // Keychains/certificate stores belonging to the OS.
    CFArrayRef certs =
        CreateKeychainItems(keychain_paths, kSecClassCertificate, keychain_map);
    // Must have returned an array of matching certificates.
    if (certs != nullptr) {
      if (CFGetTypeID(certs) == CFArrayGetTypeID()) {
        auto certificate_count = CFArrayGetCount(certs);
        for (CFIndex i = 0; i < certificate_count; i++) {
          auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
          genKeychainCertificate(cert, results, keychain_map);
        }
      }
      CFRelease(certs);
    }
  }

  // Clean up temp directory
  remove_all(keychain_map.temp_base);

  return results;
}
}
}
