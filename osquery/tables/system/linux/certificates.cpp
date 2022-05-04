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
  std::string subject_name;
  std::string subject_name2;
  std::string issuer_name;
  std::string issuer_name2;
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
  auto opt_issuer_name = getCertificateIssuerName(x509, true);
  if (opt_issuer_name.has_value()) {
    cert_info.issuer_name = opt_issuer_name.value();
  }

  opt_issuer_name = getCertificateIssuerName(x509, false);
  if (opt_issuer_name.has_value()) {
    cert_info.issuer_name2 = opt_issuer_name.value();
  }

  auto opt_subject_name = getCertificateSubjectName(x509, true);
  if (opt_subject_name.has_value()) {
    cert_info.subject_name = opt_subject_name.value();
  }

  opt_subject_name = getCertificateSubjectName(x509, false);
  if (opt_subject_name.has_value()) {
    cert_info.subject_name2 = opt_subject_name.value();
  }

  auto opt_common_name = getCertificateCommonName(x509);
  if (opt_common_name.has_value()) {
    cert_info.common_name = opt_common_name.value();
  }

  auto opt_signing_algorithm = getCertificateSigningAlgorithm(x509);
  if (opt_signing_algorithm.has_value()) {
    cert_info.signing_algorithm = opt_signing_algorithm.value();
  }

  auto opt_key_algorithm = getCertificateKeyAlgorithm(x509);
  if (opt_key_algorithm.has_value()) {
    cert_info.key_algorithm = opt_key_algorithm.value();
  }

  auto opt_key_strength = getCertificateKeyStregth(x509);
  if (opt_key_strength.has_value()) {
    cert_info.key_strength = opt_key_strength.value();
  }

  auto opt_not_valid_before = getCertificateNotValidBefore(x509);
  if (opt_not_valid_before.has_value()) {
    cert_info.not_valid_before = opt_not_valid_before.value();
  }

  auto opt_not_valid_after = getCertificateNotValidAfter(x509);
  if (opt_not_valid_after.has_value()) {
    cert_info.not_valid_after = opt_not_valid_after.value();
  }

  auto opt_digest = generateCertificateSHA1Digest(x509);
  if (opt_digest.has_value()) {
    cert_info.sha1 = opt_digest.value();
  }

  getCertificateAttributes(x509, cert_info.is_ca, cert_info.is_self_signed);

  auto opt_cert_key_usage = getCertificateKeyUsage(x509);
  if (opt_cert_key_usage.has_value()) {
    cert_info.key_usage = opt_cert_key_usage.value();
  }

  auto opt_authority_key_id = getCertificateAuthorityKeyID(x509);
  if (opt_authority_key_id.has_value()) {
    cert_info.authority_key_id = opt_authority_key_id.value();
  }

  auto opt_subject_key_id = getCertificateSubjectKeyID(x509);
  if (opt_subject_key_id.has_value()) {
    cert_info.subject_key_id = opt_subject_key_id.value();
  }

  auto opt_cert_serial_number = getCertificateSerialNumber(x509);
  if (opt_cert_serial_number.has_value()) {
    cert_info.serial = opt_cert_serial_number.value();
  }

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
      row["subject"] = SQL_TEXT(cert_info.subject_name);
      row["subject2"] = SQL_TEXT(cert_info.subject_name2);
      row["issuer"] = SQL_TEXT(cert_info.issuer_name);
      row["issuer2"] = SQL_TEXT(cert_info.issuer_name2);
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
