/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdlib>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/filesystem.hpp>

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
                            const std::string& path,
                            QueryData& results) {
  auto der_encoded_data = SecCertificateCopyData(SecCert);
  if (der_encoded_data == nullptr) {
    return;
  }

  const unsigned char* der_bytes = CFDataGetBytePtr(der_encoded_data);
  auto length = CFDataGetLength(der_encoded_data);
  auto cert = d2i_X509(nullptr, &der_bytes, length);

  if (cert != nullptr) {
    genCertificate(cert, path, results);
    X509_free(cert);
  }

  CFRelease(der_encoded_data);
}

// Copy the given keychain file to a private temp file and open the copy via
// SecKeychainOpen. Used for non-SSV-protected keychains (under
// /Library/Keychains and ~/Library/Keychains). On macOS 26+, passing the live
// user keychain file to SecKeychainOpen can corrupt it; the copy is
// disposable and is cleaned up by the caller.
//
// On success, populates *keychain_out with the opened SecKeychainRef (caller
// releases) and temp_path_out with the temp file path (caller deletes), and
// returns true. Returns false on any failure, with *keychain_out == nullptr.
static bool copyAndOpenKeychain(const std::string& original_path,
                                std::string& temp_path_out,
                                SecKeychainRef* keychain_out) {
  *keychain_out = nullptr;
  temp_path_out.clear();

  boost::filesystem::path orig(original_path);
  std::string suffix = orig.extension().string();

  const char* env_tmpdir = std::getenv("TMPDIR");
  std::string tmpl =
      (env_tmpdir != nullptr && env_tmpdir[0] != '\0') ? env_tmpdir : "/tmp";
  if (tmpl.back() != '/') {
    tmpl.push_back('/');
  }
  tmpl += "osquery-kc-XXXXXX";
  tmpl += suffix;

  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');

  int fd = mkstemps(buf.data(), static_cast<int>(suffix.size()));
  if (fd < 0) {
    return false;
  }
  ::close(fd);
  std::string temp_path(buf.data());

  boost::system::error_code ec;
  boost::filesystem::copy_file(
      orig, temp_path, boost::filesystem::copy_options::overwrite_existing, ec);
  if (ec.failed()) {
    boost::filesystem::remove(temp_path, ec);
    return false;
  }

  SecKeychainRef keychain = nullptr;
  OSStatus status;
  OSQUERY_USE_DEPRECATED(status =
                             SecKeychainOpen(temp_path.c_str(), &keychain));
  if (status != errSecSuccess || keychain == nullptr) {
    if (keychain != nullptr) {
      CFRelease(keychain);
    }
    boost::filesystem::remove(temp_path, ec);
    return false;
  }

  *keychain_out = keychain;
  temp_path_out = std::move(temp_path);
  return true;
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

  // RAII cleanup for keychain refs and temp-file copies: runs on normal exit,
  // early return, or exception. Refs are released before temp files are
  // unlinked so Security.framework holds no handle on a copy when it's
  // removed.
  struct KeychainCleanup {
    std::vector<SecKeychainRef> refs;
    std::vector<std::string> temp_files;
    ~KeychainCleanup() {
      for (SecKeychainRef ref : refs) {
        CFRelease(ref);
      }
      boost::system::error_code ec;
      for (const auto& tf : temp_files) {
        boost::filesystem::remove(tf, ec);
      }
    }
  } cleanup;

  @autoreleasepool {
    auto& temp_files = cleanup.temp_files;
    auto& opened_refs = cleanup.refs;

    // Map of user-provided path to (canonical source, hash, opened keychain).
    // Ensures we don't open the same keychain twice when a path constraint
    // is specified.
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
        bool opened = false;
        if (isSSVProtectedPath(source.string())) {
          // /System/Library/Keychains/*
          //
          // SSV-protected keychains are on a read-only volume; opening them
          // directly via the legacy API cannot corrupt them.
          SecKeychainStatus keychain_status;
          OSStatus status;
          OSQUERY_USE_DEPRECATED(status =
                                     SecKeychainOpen(path.c_str(), &keychain));
          if (status == errSecSuccess && keychain != nullptr) {
            OSQUERY_USE_DEPRECATED(
                status = SecKeychainGetStatus(keychain, &keychain_status));
            if (status == errSecSuccess) {
              opened = true;
            }
          }
          if (!opened && keychain != nullptr) {
            CFRelease(keychain);
            keychain = nullptr;
          }
        } else {
          // ~/Library/Keychains/* and /Library/Keychains/*
          //
          // Non-SSV: copy the file to a private temp path and open the copy.
          // Calling SecKeychainOpen on the live user file can corrupt it on
          // macOS 26+.
          std::string temp_path;
          if (copyAndOpenKeychain(source.string(), temp_path, &keychain)) {
            temp_files.push_back(temp_path);
            opened = true;
          }
        }

        if (!opened) {
          // Either the open failed outright or the file isn't a keychain.
          // Fall back to treating it as a DER/PEM cert file on disk.
          QueryData new_results;
          genFileCertificate(path, new_results);
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, new_results);
          results.insert(results.end(), new_results.begin(), new_results.end());
          continue;
        }

        opened_refs.push_back(keychain);
        keychain_paths.insert(path);
        opened_keychains.insert(
            {path, std::make_tuple(source, hash, keychain)});
      }
    } else {
      keychain_paths = getKeychainPaths();
    }

    // Since we use a cache per keychain file, we must process certificates
    // one keychain file at a time.
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
          // File does not exist or user does not have access. Don't log here
          // to reduce noise.
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

        // Cache miss: open the keychain using the path-appropriate strategy.
        if (isSSVProtectedPath(source.string())) {
          // /System/Library/Keychains/*
          OSStatus status;
          OSQUERY_USE_DEPRECATED(
              status = SecKeychainOpen(source.c_str(), &keychain));
          if (status != errSecSuccess || keychain == nullptr) {
            if (keychain != nullptr) {
              CFRelease(keychain);
              keychain = nullptr;
            }
          }
        } else {
          // ~/Library/Keychains/* and /Library/Keychains/*
          //
          // Non-SSV: copy the file to a private temp path and open the copy.
          // Calling SecKeychainOpen on the live user file can corrupt it on
          // macOS 26+.
          std::string temp_path;
          if (copyAndOpenKeychain(source.string(), temp_path, &keychain)) {
            temp_files.push_back(temp_path);
          }
        }

        if (keychain == nullptr) {
          // Cache an empty result to prevent the above API call in the
          // future.
          keychainCache.Write(source, KEYCHAIN_TABLE, hash, {});
          continue;
        }
        opened_refs.push_back(keychain);
      }

      auto keychains = CFArrayCreateMutable(nullptr, 1, &kCFTypeArrayCallBacks);
      CFArrayAppendValue(keychains, keychain);
      QueryData new_results;
      // Query certificates in this one keychain via SecItemCopyMatching.
      CFArrayRef certs = CreateKeychainItems(keychains, kSecClassCertificate);
      CFRelease(keychains);
      if (certs != nullptr) {
        if (CFGetTypeID(certs) == CFArrayGetTypeID()) {
          auto certificate_count = CFArrayGetCount(certs);
          for (CFIndex i = 0; i < certificate_count; i++) {
            auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
            // Attribute the row to the original path, not the temp copy.
            genKeychainCertificate(cert, source.string(), new_results);
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
