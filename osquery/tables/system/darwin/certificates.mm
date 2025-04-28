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

// The table key for Keychain cache access.
static const KeychainTable KEYCHAIN_TABLE = KeychainTable::CERTIFICATES;

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
  // If the serial number is <= 8 bytes, translate it from
  // hex to decimal.
  if (opt_cert_serial_number.has_value()) {
    auto serial = opt_cert_serial_number.value();
    if (serial.size() <= 16) {
      unsigned long decimal_serial = strtoul(serial.c_str(), nullptr, 16);
      r["serial"] = SQL_TEXT(decimal_serial);
    } else {
      r["serial"] = SQL_TEXT(serial);
    }
  }

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

  // Lock keychain access to 1 table/thread at a time.
  std::unique_lock<decltype(keychainMutex)> lock(keychainMutex);

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

  @autoreleasepool {
    // Map of path to hash and keychain reference. This ensures we don't open
    // the same keychain multiple times when the table's path constraint is
    // used.
    std::map<std::string,
             std::tuple<boost::filesystem::path, std::string, SecKeychainRef>>
        opened_keychains;
    if (!paths.empty()) {
      for (const auto& path : paths) {
        // Check whether path is valid
        boost::system::error_code ec;
        auto source =
            boost::filesystem::canonical(boost::filesystem::path(path), ec);
        if (ec.failed() || !is_regular_file(source, ec) || ec.failed()) {
          TLOG << "Could not access file " << path << " " << ec.message();
          continue;
        }

        // Check cache
        bool err = false;
        std::string hash;
        bool hit =
            keychainCache.Read(source, KEYCHAIN_TABLE, hash, results, err);
        if (err) {
          TLOG << "Could not read the file at " << path << "" << ec.message();
          continue;
        }
        if (hit) {
          continue;
        }

        SecKeychainRef keychain = nullptr;
        SecKeychainStatus keychain_status;
        OSStatus status;
        OSQUERY_USE_DEPRECATED(status =
                                   SecKeychainOpen(path.c_str(), &keychain));
        bool genFileCert = false;
        if (status != errSecSuccess || keychain == nullptr) {
          genFileCert = true;
        } else {
          OSQUERY_USE_DEPRECATED(
              status = SecKeychainGetStatus(keychain, &keychain_status));
          if (status != errSecSuccess) {
            genFileCert = true;
          }
        }
        if (genFileCert) {
          if (keychain != nullptr) {
            CFRelease(keychain);
          }
          QueryData new_results;
          genFileCertificate(path, new_results);
          // Write new results to the cache.
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
          results.insert(results.end(), new_results.begin(), new_results.end());
        } else {
          // This path will be re-accessed later.
          keychain_paths.insert(path);
          opened_keychains.insert(
              {path, std::make_tuple(source, hash, keychain)});
        }
      }
    } else {
      keychain_paths = getKeychainPaths();
    }

    // Since we are used a cache for each keychain file, we must process
    // certificates one keychain file at a time.
    std::set<std::string> expanded_paths = expandPaths(keychain_paths);
    for (const auto& path : expanded_paths) {
      SecKeychainRef keychain = nullptr;
      std::string hash;
      boost::filesystem::path source;
      auto it = opened_keychains.find(path);
      if (it != opened_keychains.end()) {
        source = std::get<0>(it->second);
        hash = std::get<1>(it->second);
        keychain = std::get<2>(it->second);
      } else {
        // Check whether path is valid
        boost::system::error_code ec;
        source =
            boost::filesystem::canonical(boost::filesystem::path(path), ec);
        if (ec.failed() || !is_regular_file(source, ec) || ec.failed()) {
          // File does not exist or user does not have access. Don't log here to
          // reduce noise.
          continue;
        }

        // Check cache
        bool err = false;
        bool hit =
            keychainCache.Read(source, KEYCHAIN_TABLE, hash, results, err);
        if (err) {
          TLOG << "Could not read the file at " << source.string() << ""
               << ec.message();
          continue;
        }
        if (hit) {
          continue;
        }

        // Cache miss. We need to generate new results.
        OSStatus status;
        OSQUERY_USE_DEPRECATED(status =
                                   SecKeychainOpen(source.c_str(), &keychain));
        if (status != errSecSuccess || keychain == nullptr) {
          if (keychain != nullptr) {
            CFRelease(keychain);
          }
          // Cache an empty result to prevent the above API call in the future.
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
          continue;
        }
      }

      auto keychains = CFArrayCreateMutable(nullptr, 1, &kCFTypeArrayCallBacks);
      CFArrayAppendValue(keychains, keychain);
      QueryData new_results;
      // Keychains/certificate stores belonging to the OS.
      CFArrayRef certs = CreateKeychainItems(keychains, kSecClassCertificate);
      CFRelease(keychains);
      // Must have returned an array of matching certificates.
      if (certs != nullptr) {
        if (CFGetTypeID(certs) == CFArrayGetTypeID()) {
          auto certificate_count = CFArrayGetCount(certs);
          for (CFIndex i = 0; i < certificate_count; i++) {
            auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
            genKeychainCertificate(cert, new_results);
          }
        }
        CFRelease(certs);
        keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
        results.insert(results.end(), new_results.begin(), new_results.end());
      } else {
        // Cache an empty result to prevent the above API call in the future.
        keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
      }
    }
  }

  if (FLAGS_keychain_access_cache) {
    TLOG << "Total Keychain Cache entries: " << keychainCache.Size();
  }

  return results;
}
}
}
