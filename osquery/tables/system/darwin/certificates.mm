/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/opensslv.h>
#include <openssl/x509.h>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>

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

// Temporary workaround for Buck compiling with an older openssl version
#if OPENSSL_VERSION_NUMBER < 0x10101000L
  r["key_usage"] = genKeyUsage(cert->ex_kusage);
  r["authority_key_id"] =
      (cert->akid && cert->akid->keyid)
          ? genKIDProperty(cert->akid->keyid->data, cert->akid->keyid->length)
          : "";
  r["subject_key_id"] =
      (cert->skid) ? genKIDProperty(cert->skid->data, cert->skid->length) : "";
#else
  r["key_usage"] = genKeyUsage(X509_get_key_usage(cert));

  const auto* cert_key_id = X509_get0_authority_key_id(cert);
  r["authority_key_id"] =
      cert_key_id ? genKIDProperty(cert_key_id->data, cert_key_id->length) : "";

  cert_key_id = X509_get0_subject_key_id(cert);
  r["subject_key_id"] =
      cert_key_id ? genKIDProperty(cert_key_id->data, cert_key_id->length) : "";
#endif

  r["serial"] = genSerialForCertificate(cert);

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

  @autoreleasepool {
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
    CFArrayRef certs =
        CreateKeychainItems(keychain_paths, kSecClassCertificate);
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
  }
  return results;
}
}
}
