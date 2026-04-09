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
  r["serial"] = SQL_TEXT(opt_cert_serial_number.value_or(""));

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

  // Expand paths from query constraints.
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
    // Determine which paths are in the default keychain search list (Tier 1,
    // safe) vs non-standard paths that need SecKeychainOpen (Tier 2, legacy).
    auto default_kc_paths = getDefaultKeychainPaths();

    std::set<std::string> standard_paths;
    std::set<std::string> nonstandard_paths;

    if (!paths.empty()) {
      for (const auto& path : paths) {
        boost::system::error_code ec;
        auto source =
            boost::filesystem::canonical(boost::filesystem::path(path), ec);
        if (ec.failed() || !is_regular_file(source, ec) || ec.failed()) {
          TLOG << "Could not access file " << path << " " << ec.message();
          continue;
        }

        if (default_kc_paths.count(source.string()) > 0) {
          standard_paths.insert(source.string());
        } else {
          nonstandard_paths.insert(path);
        }
      }
    } else {
      // No path constraints: enumerate all default keychain directories.
      auto kc_dirs = getKeychainPaths();
      auto expanded = expandPaths(kc_dirs);
      for (const auto& p : expanded) {
        boost::system::error_code ec;
        auto source =
            boost::filesystem::canonical(boost::filesystem::path(p), ec);
        if (!ec.failed() && is_regular_file(source, ec) && !ec.failed()) {
          if (default_kc_paths.count(source.string()) > 0) {
            standard_paths.insert(source.string());
          } else {
            nonstandard_paths.insert(p);
          }
        }
      }
    }

    // --- Tier 1: Safe path using SecItemCopyMatching without SecKeychainOpen.
    // Check per-path cache for standard paths first.
    // Map of cache-miss paths to their file hashes.
    std::map<std::string, std::string> cache_miss_hashes;

    for (const auto& spath : standard_paths) {
      boost::filesystem::path source(spath);
      bool err = false;
      std::string hash;
      bool hit =
          keychainCache.Read(source, KEYCHAIN_TABLE, hash, results, err);
      if (err) {
        TLOG << "Could not read the file at " << spath;
        continue;
      }
      if (!hit) {
        cache_miss_hashes[spath] = hash;
      }
    }

    if (!cache_miss_hashes.empty()) {
      CFArrayRef certs = CreateAllKeychainCertificates();
      if (certs != nullptr && CFGetTypeID(certs) == CFArrayGetTypeID()) {
        // Partition results by keychain path.
        std::map<std::string, QueryData> partitioned;
        auto count = CFArrayGetCount(certs);
        for (CFIndex i = 0; i < count; i++) {
          auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
          auto cert_path = getKeychainPath((SecKeychainItemRef)cert);

          if (cache_miss_hashes.count(cert_path) > 0) {
            genKeychainCertificate(cert, partitioned[cert_path]);
          }
        }

        // Write each partition to cache and append to results.
        for (auto& [path, new_results] : partitioned) {
          keychainCache.Write(boost::filesystem::path(path),
                              KEYCHAIN_TABLE,
                              cache_miss_hashes[path],
                              new_results);
          results.insert(
              results.end(), new_results.begin(), new_results.end());
          cache_miss_hashes.erase(path);
        }

        CFRelease(certs);
      }

      // Any remaining cache-miss paths had no certificates; cache empty.
      for (const auto& [path, hash] : cache_miss_hashes) {
        keychainCache.Write(
            boost::filesystem::path(path), KEYCHAIN_TABLE, hash, {});
      }
    }

    // --- Tier 2: Legacy path for non-standard keychains and cert files.
    // Uses SecKeychainOpen as a fallback (risk accepted for non-standard paths).
    std::set<std::string> expanded_nonstandard = expandPaths(nonstandard_paths);
    for (const auto& path : expanded_nonstandard) {
      boost::system::error_code ec;
      auto source =
          boost::filesystem::canonical(boost::filesystem::path(path), ec);
      if (ec.failed() || !is_regular_file(source, ec) || ec.failed()) {
        continue;
      }

      bool err = false;
      std::string hash;
      bool hit =
          keychainCache.Read(source, KEYCHAIN_TABLE, hash, results, err);
      if (err || hit) {
        continue;
      }

      // Try opening as a keychain database first.
      SecKeychainRef keychain = nullptr;
      SecKeychainStatus keychain_status;
      OSStatus status;
      OSQUERY_USE_DEPRECATED(status =
                                 SecKeychainOpen(path.c_str(), &keychain));

      bool use_file_cert = false;
      if (status != errSecSuccess || keychain == nullptr) {
        use_file_cert = true;
      } else {
        OSQUERY_USE_DEPRECATED(
            status = SecKeychainGetStatus(keychain, &keychain_status));
        if (status != errSecSuccess) {
          use_file_cert = true;
        }
      }

      if (use_file_cert) {
        if (keychain != nullptr) {
          CFRelease(keychain);
        }
        QueryData new_results;
        genFileCertificate(path, new_results);
        keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
        results.insert(results.end(), new_results.begin(), new_results.end());
      } else {
        auto keychains =
            CFArrayCreateMutable(nullptr, 1, &kCFTypeArrayCallBacks);
        CFArrayAppendValue(keychains, keychain);
        QueryData new_results;
        CFArrayRef items =
            CreateKeychainItems(keychains, kSecClassCertificate);
        CFRelease(keychains);
        if (items != nullptr) {
          if (CFGetTypeID(items) == CFArrayGetTypeID()) {
            auto cert_count = CFArrayGetCount(items);
            for (CFIndex i = 0; i < cert_count; i++) {
              auto cert =
                  (SecCertificateRef)CFArrayGetValueAtIndex(items, i);
              genKeychainCertificate(cert, new_results);
            }
          }
          CFRelease(items);
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
          results.insert(
              results.end(), new_results.begin(), new_results.end());
        } else {
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
        }
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
