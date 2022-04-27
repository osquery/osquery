/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/posix/openssl_utils.h>
#include <osquery/utils/expected/expected.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <filesystem>

namespace osquery::tables {

namespace {

static const std::vector<std::filesystem::path> kDefaultBundlePathList{
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
};

using BIODeleter = int (*)(BIO*);
using UniqueBIO = std::unique_ptr<BIO, BIODeleter>;

using X509InfoStackDeleter = void (*)(stack_st_X509_INFO*);
using UniqueX509InfoStack =
    std::unique_ptr<stack_st_X509_INFO, X509InfoStackDeleter>;

using X509InfoDeleter = void (*)(X509_INFO*);
using UniqueX509Info = std::unique_ptr<X509_INFO, X509InfoDeleter>;
using UniqueX509InfoList = std::vector<UniqueX509Info>;

struct CertificateInformation final {
  std::string common_name;
  std::string subject;
  std::string issuer;
  std::time_t not_valid_before;
  std::time_t not_valid_after;
  std::string signing_algorithm;
  std::string key_algorithm;
  std::string key_strength;
  std::string key_usage;
  std::string subject_key_id;
  std::string authority_key_id;
  std::string sha1;
  std::string serial;
  bool is_ca{false};
  bool is_self_signed{false};
};

using CertificateInformationList = std::vector<CertificateInformation>;

enum class OpenSSLError {
  OpenFailed,
  ReadFailed,
  InvalidX509Info,
  InvalidX509,
};

Expected<UniqueBIO, OpenSSLError> createFileBasedBIO(
    const std::filesystem::path& path) {
  auto bio_ptr = BIO_new_file(path.string().c_str(), "r");
  if (bio_ptr == nullptr) {
    return createError(OpenSSLError::OpenFailed)
           << "Failed to open the following file: " << path;
  }

  return UniqueBIO(bio_ptr, BIO_free);
}

Expected<UniqueX509InfoStack, OpenSSLError> readCertificateStackFromBIO(
    BIO* bio) {
  auto stack_ptr = PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
  if (stack_ptr == nullptr) {
    return createError(OpenSSLError::ReadFailed)
           << "Failed to read from the certificate file";
  }

  return UniqueX509InfoStack(stack_ptr, sk_X509_INFO_free);
}

Expected<CertificateInformation, OpenSSLError> generateCertificateInformation(
    X509_INFO* x509_info) {
  if (x509_info == nullptr) {
    return createError(OpenSSLError::InvalidX509Info);
  }

  auto x509 = x509_info->x509;
  if (x509 == nullptr) {
    return createError(OpenSSLError::InvalidX509);
  }

  CertificateInformation cert_info;
  genCommonName(
      x509, cert_info.subject, cert_info.common_name, cert_info.issuer);

  genAlgorithmProperties(x509,
                         cert_info.key_algorithm,
                         cert_info.signing_algorithm,
                         cert_info.key_strength);

  cert_info.not_valid_before = genEpoch(X509_get_notBefore(x509));
  cert_info.not_valid_after = genEpoch(X509_get_notAfter(x509));

  cert_info.sha1 = genSHA1ForCertificate(x509);
  cert_info.is_ca = certificateIsCA(x509);
  cert_info.is_self_signed = certificateIsSelfSigned(x509);
  cert_info.key_usage = genKeyUsage(X509_get_key_usage(x509));

  const auto* cert_key_id = X509_get0_authority_key_id(x509);
  if (cert_key_id != nullptr) {
    cert_info.authority_key_id =
        genKIDProperty(cert_key_id->data, cert_key_id->length);
  }

  cert_key_id = X509_get0_subject_key_id(x509);
  if (cert_key_id != nullptr) {
    cert_info.subject_key_id =
        genKIDProperty(cert_key_id->data, cert_key_id->length);
  }

  cert_info.serial = genSerialForCertificate(x509);

  return cert_info;
}

Expected<CertificateInformationList, OpenSSLError> parseX509InfoStack(
    UniqueX509InfoList x509_info_list) {
  CertificateInformationList cert_info_list;

  for (auto& x509_info : x509_info_list) {
    auto exp_cert_info = generateCertificateInformation(x509_info.get());
    if (exp_cert_info.isError()) {
      return exp_cert_info.takeError();
    }

    auto cert_info = exp_cert_info.take();
    cert_info_list.push_back(std::move(cert_info));
  }

  return cert_info_list;
}

Expected<CertificateInformationList, OpenSSLError> enumerateBundleCertificates(
    const std::filesystem::path& path) {
  // Open the bundle file
  auto exp_cert_bundle = createFileBasedBIO(path);
  if (exp_cert_bundle.isError()) {
    return exp_cert_bundle.takeError();
  }

  auto cert_bundle = exp_cert_bundle.take();

  // Read all the certificates into a stack of X509_INFO structures
  auto exp_cert_info_stack = readCertificateStackFromBIO(cert_bundle.get());
  if (exp_cert_info_stack.isError()) {
    return exp_cert_info_stack.takeError();
  }

  auto cert_info_stack = exp_cert_info_stack.take();

  // Filter out the entries that we do not want
  UniqueX509InfoList x509_info_list;

  while (sk_X509_INFO_num(cert_info_stack.get())) {
    UniqueX509Info x509_info(nullptr, X509_INFO_free);

    {
      auto x509_info_ptr = sk_X509_INFO_shift(cert_info_stack.get());
      x509_info.reset(x509_info_ptr);
    }

    if (x509_info->x509 != nullptr) {
      x509_info_list.push_back(std::move(x509_info));
    }
  }

  return parseX509InfoStack(std::move(x509_info_list));
}

} // namespace

QueryData genCerts(QueryContext& context) {
  QueryData results;

  std::vector<std::filesystem::path> bundle_path_list;

  auto user_path_list = context.constraints["path"].getAll(EQUALS);
  if (user_path_list.empty()) {
    bundle_path_list = kDefaultBundlePathList;

  } else {
    for (const auto& user_path : user_path_list) {
      bundle_path_list.push_back(user_path);
    }
  }

  for (const auto& bundle_path : bundle_path_list) {
    auto exp_cert_info_list = enumerateBundleCertificates(bundle_path);
    if (exp_cert_info_list.isError()) {
      auto error = exp_cert_info_list.takeError();
      LOG(ERROR) << error.getMessage();

      continue;
    }

    auto cert_info_list = exp_cert_info_list.take();

    for (const auto& cert_info : cert_info_list) {
      Row row;
      row["path"] = SQL_TEXT(bundle_path.string());
      row["common_name"] = SQL_TEXT(cert_info.common_name);
      row["subject"] = SQL_TEXT(cert_info.subject);
      row["issuer"] = SQL_TEXT(cert_info.issuer);
      row["ca"] = INTEGER(cert_info.is_ca ? 1 : 0);
      row["self_signed"] = INTEGER(cert_info.is_self_signed ? 1 : 0);
      row["not_valid_before"] = INTEGER(cert_info.not_valid_before);
      row["not_valid_after"] = INTEGER(cert_info.not_valid_after);
      row["signing_algorithm"] = SQL_TEXT(cert_info.signing_algorithm);
      row["key_algorithm"] = SQL_TEXT(cert_info.key_algorithm);
      row["key_strength"] = SQL_TEXT(cert_info.key_strength);
      row["key_usage"] = SQL_TEXT(cert_info.key_usage);
      row["subject_key_id"] = SQL_TEXT(cert_info.subject_key_id);
      row["authority_key_id"] = SQL_TEXT(cert_info.authority_key_id);
      row["sha1"] = SQL_TEXT(cert_info.sha1);
      row["serial"] = SQL_TEXT(cert_info.serial);

      results.push_back(std::move(row));
    }
  }

  return results;
}

} // namespace osquery::tables
