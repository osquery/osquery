/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unistd.h>

#include <copyfile.h>

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

// True iff the file at `path` looks like a container SecKeychainOpen can
// parse. Positive identification by leading bytes, so unknown files under
// the keychain directories are skipped by default and any new file type
// with a legacy-keychain magic is auto-accepted.
//
// Two legacy keychain formats are accepted by SecKeychainOpen:
//   1. CSSM "Mac OS X Keychain File" — 4-byte "kych" magic at offset 0.
//      Covers System.keychain, apsd.keychain, SystemRootCertificates.keychain,
//      X509Anchors, etc. Magic bytes are a bulletproof positive signal.
//   2. SQLite-backed legacy keychain — "SQLite format 3\0" at offset 0.
//      SQLite magic alone is ambiguous: Data Protection Keychain databases
//      (keychain-2.db) share it. We additionally require the basename to
//      end with ".keychain-db" and not with "keychain-2.db" to
//      disambiguate. Covers login.keychain-db, metadata.keychain-db.
//
// We use this to prevent securityd logging the following messages when SecKeychainOpen
// attempts to parse files that are not supported keychain formats:
//  osqueryd: (Security) [com.apple.securityd:integrity] dbBlobVersion() failed for a CssmError: -2147413759 CSSMERR_DL_DATABASE_CORRUPT
//  osqueryd: (Security) [com.apple.securityd:security_exception] CSSM Exception: -2147413759 CSSMERR_DL_DATABASE_CORRUPT
static bool isLegacyKeychainFile(const std::string& path) {
  std::array<char, 16> header{};
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  in.read(header.data(), header.size());
  std::streamsize read = in.gcount();

  static constexpr char kCssmMagic[4] = {'k', 'y', 'c', 'h'};
  if (read >= 4 &&
      std::memcmp(header.data(), kCssmMagic, sizeof(kCssmMagic)) == 0) {
    return true;
  }

  // "SQLite format 3" + trailing null byte, 16 bytes total.
  static constexpr char kSqliteMagic[16] = {'S',
                                            'Q',
                                            'L',
                                            'i',
                                            't',
                                            'e',
                                            ' ',
                                            'f',
                                            'o',
                                            'r',
                                            'm',
                                            'a',
                                            't',
                                            ' ',
                                            '3',
                                            '\0'};
  if (read == static_cast<std::streamsize>(header.size()) &&
      std::memcmp(header.data(), kSqliteMagic, sizeof(kSqliteMagic)) == 0) {
    std::string name = boost::filesystem::path(path).filename().string();
    auto ends_with = [&](const char* suffix) {
      size_t len = std::strlen(suffix);
      return name.size() >= len &&
             name.compare(name.size() - len, len, suffix) == 0;
    };
    return ends_with(".keychain-db") && !ends_with("keychain-2.db");
  }

  return false;
}

// Copy the given keychain file into a private temp directory and open the
// copy via SecKeychainOpen. Used for non-SSV-protected keychains (under
// /Library/Keychains and ~/Library/Keychains). On macOS 26+, passing the live
// user keychain file to SecKeychainOpen can corrupt it; the copy is
// disposable and the caller removes the whole temp directory.
//
// The copy goes through copyfile(3) with COPYFILE_CLONE: on APFS this is an
// atomic clonefile(2) snapshot (immune to concurrent writes by securityd) and
// preserves ACLs + extended attributes that Security.framework's integrity
// checks may consult. On non-APFS volumes copyfile silently falls back to a
// regular copy that still copies xattrs and ACLs.
//
// On success, populates *keychain_out with the opened SecKeychainRef (caller
// releases) and temp_dir_out with the temp directory (caller removes with
// remove_all). Returns false on any failure with *keychain_out == nullptr
// and the temp directory already removed.
static bool copyAndOpenKeychain(const std::string& original_path,
                                std::string& temp_dir_out,
                                SecKeychainRef* keychain_out) {
  *keychain_out = nullptr;
  temp_dir_out.clear();

  boost::filesystem::path orig(original_path);
  std::string filename = orig.filename().string();
  if (filename.empty()) {
    return false;
  }

  boost::system::error_code ec;
  boost::filesystem::path tmp_root = boost::filesystem::temp_directory_path(ec);
  if (ec) {
    return false;
  }
  std::string dir_tmpl = (tmp_root / "osquery-kc-XXXXXX").string();

  if (mkdtemp(dir_tmpl.data()) == nullptr) {
    return false;
  }
  std::string temp_dir(dir_tmpl);
  std::string temp_path = temp_dir + "/" + filename;

  // COPYFILE_CLONE: atomic APFS clonefile snapshot when possible, copying
  // data + ACLs + xattrs. Falls back to a regular copy (still with ACL/xattr)
  // on filesystems that don't support cloning.
  if (copyfile(
          original_path.c_str(), temp_path.c_str(), nullptr, COPYFILE_CLONE) !=
      0) {
    boost::system::error_code rm_ec;
    boost::filesystem::remove_all(temp_dir, rm_ec);
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
    boost::system::error_code rm_ec;
    boost::filesystem::remove_all(temp_dir, rm_ec);
    return false;
  }

  *keychain_out = keychain;
  temp_dir_out = std::move(temp_dir);
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

  // RAII cleanup for keychain refs and temp-directory copies: runs on normal
  // exit, early return, or exception. Refs are released before temp dirs are
  // removed so Security.framework holds no handle on a copy when it's
  // unlinked.
  struct KeychainCleanup {
    std::vector<SecKeychainRef> refs;
    std::vector<std::string> temp_dirs;
    ~KeychainCleanup() {
      for (SecKeychainRef ref : refs) {
        CFRelease(ref);
      }
      boost::system::error_code ec;
      for (const auto& td : temp_dirs) {
        boost::filesystem::remove_all(td, ec);
      }
    }
  } cleanup;

  @autoreleasepool {
    auto& temp_dirs = cleanup.temp_dirs;
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
        if (!isLegacyKeychainFile(source.string())) {
          // Not a legacy keychain container the SecKeychain API can parse.
          // Leave `opened` false so we fall through to the DER/PEM path.
        } else if (isSSVProtectedPath(source.string())) {
          // /System/Library/Keychains/*
          //
          // SSV-protected keychains are on a read-only volume; opening them
          // directly via the legacy API does not seem to corrupt them.
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
          // Non-SSV: copy the file to a private temp dir and open the copy.
          // Calling SecKeychainOpen on the live user file can corrupt it on
          // macOS 26+.
          std::string temp_dir;
          if (copyAndOpenKeychain(source.string(), temp_dir, &keychain)) {
            temp_dirs.push_back(temp_dir);
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

        // Skip anything that isn't a legacy keychain container. Feeding
        // non-keychains to SecKeychainOpen/SecItemCopyMatching produces
        // CSSMERR_DL_DATABASE_CORRUPT / dbBlobVersion() errors in the
        // unified log when Security.framework tries to parse the blob.
        if (!isLegacyKeychainFile(source.string())) {
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
          // Non-SSV: copy the file to a private temp dir and open the copy.
          std::string temp_dir;
          if (copyAndOpenKeychain(source.string(), temp_dir, &keychain)) {
            temp_dirs.push_back(temp_dir);
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
