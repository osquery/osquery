/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/posix/openssl_utils.h>
#include <osquery/utils/expected/expected.h>

#include <openssl/x509.h>

#include <boost/optional.hpp>

#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace osquery{
namespace tables{

namespace {
// The first 4 bytes of an efivars file are EFI variable attributes, not data.
static constexpr std::size_t kEfiVarAttributeSize = 4U;

// EFI_SIGNATURE_LIST header layout (28 bytes total):
//   [0..15]  SignatureType GUID
//   [16..19] SignatureListSize  (LE uint32)
//   [20..23] SignatureHeaderSize (LE uint32)
//   [24..27] SignatureSize      (LE uint32)
static constexpr std::size_t kEslHeaderSize = 28U;

// Each EFI_SIGNATURE_DATA entry is prefixed with a 16-byte SignatureOwner GUID
// before the actual signature payload (e.g. DER certificate bytes).
static constexpr std::size_t kSignatureOwnerGuidSize = 16U;

// First byte of EFI_CERT_X509_GUID as stored on disk in little-endian order.
// EFI_CERT_X509_GUID = {0xa5c059a1, ...} -> disk byte 0 == 0xa1
static constexpr uint8_t kX509GuidFirstByte = 0xa1U;

// Minimum ESL payload size we consider meaningful.
static constexpr std::size_t kMinEslSize = 28U;

// EFI secure boot signature stores to read, with their canonical store names.
// EFI_IMAGE_SECURITY_DATABASE_GUID = d719b2cb-3d3a-4596-a3bc-dad00e67656f
static const std::vector<std::pair<std::string, std::string>> kEfiDbGlobs{
    {"/sys/firmware/efi/efivars/db-*", "db"},
    {"/sys/firmware/efi/efivars/dbx-*", "dbx"},
};

using X509Deleter = void (*)(X509*);
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

struct EfiCertInfo {
  std::string common_name;
  std::string subject;
  std::string issuer;
  std::time_t not_valid_before{0};
  std::time_t not_valid_after{0};
  std::string sha1;
  std::string serial;
  bool is_ca{false};
  bool is_self_signed{false};
  std::string key_usage;
  std::string authority_key_id;
  std::string subject_key_id;
  std::string signing_algorithm;
  std::string key_algorithm;
  std::string key_strength;
};

} // namespace

uint32_t readLE32(const uint8_t* buf) {
  return static_cast<uint32_t>(buf[0]) |
         (static_cast<uint32_t>(buf[1]) << 8U) |
         (static_cast<uint32_t>(buf[2]) << 16U) |
         (static_cast<uint32_t>(buf[3]) << 24U);
}

boost::optional<EfiCertInfo> parseDerCertificate(const uint8_t* data,
                                                  std::size_t len) {
  const uint8_t* ptr = data;
  UniqueX509 cert(d2i_X509(nullptr, &ptr, static_cast<long>(len)), X509_free);
  if (!cert) {
    return boost::none;
  }

  EfiCertInfo info;

  auto opt_common_name = getCertificateCommonName(cert.get());
  if (opt_common_name.has_value()) {
    info.common_name = opt_common_name.value();
  }

  auto opt_subject = getCertificateSubjectName(cert.get(), true);
  if (opt_subject.has_value()) {
    info.subject = opt_subject.value();
  }

  auto opt_issuer = getCertificateIssuerName(cert.get(), true);
  if (opt_issuer.has_value()) {
    info.issuer = opt_issuer.value();
  }

  auto opt_not_valid_before = getCertificateNotValidBefore(cert.get());
  if (opt_not_valid_before.has_value()) {
    info.not_valid_before = opt_not_valid_before.value();
  }

  auto opt_not_valid_after = getCertificateNotValidAfter(cert.get());
  if (opt_not_valid_after.has_value()) {
    info.not_valid_after = opt_not_valid_after.value();
  }

  auto opt_sha1 = generateCertificateSHA1Digest(cert.get());
  if (opt_sha1.has_value()) {
    info.sha1 = opt_sha1.value();
  }

  auto opt_serial = getCertificateSerialNumber(cert.get());
  if (opt_serial.has_value()) {
    info.serial = opt_serial.value();
  }

  getCertificateAttributes(cert.get(), info.is_ca, info.is_self_signed);

  auto opt_key_usage = getCertificateKeyUsage(cert.get());
  if (opt_key_usage.has_value()) {
    info.key_usage = opt_key_usage.value();
  }

  auto opt_authority_key_id = getCertificateAuthorityKeyID(cert.get());
  if (opt_authority_key_id.has_value()) {
    info.authority_key_id = opt_authority_key_id.value();
  }

  auto opt_subject_key_id = getCertificateSubjectKeyID(cert.get());
  if (opt_subject_key_id.has_value()) {
    info.subject_key_id = opt_subject_key_id.value();
  }

  auto opt_signing_algorithm = getCertificateSigningAlgorithm(cert.get());
  if (opt_signing_algorithm.has_value()) {
    info.signing_algorithm = opt_signing_algorithm.value();
  }

  auto opt_key_algorithm = getCertificateKeyAlgorithm(cert.get());
  if (opt_key_algorithm.has_value()) {
    info.key_algorithm = opt_key_algorithm.value();
  }

  auto opt_key_strength = getCertificateKeyStregth(cert.get());
  if (opt_key_strength.has_value()) {
    info.key_strength = opt_key_strength.value();
  }

  return info;
}

// Parse a sequence of concatenated EFI_SIGNATURE_LIST structures and add any
// X.509 certificates found to results.
void parseEslData(const std::string& content,
                  const std::string& store,
                  const std::string& path,
                  QueryData& results) {
  if (content.size() < kEfiVarAttributeSize + kMinEslSize) {
    VLOG(1) << "secureboot_certificates: ESL data too short in " << path;
    return;
  }

  const uint8_t* data = reinterpret_cast<const uint8_t*>(content.data());
  std::size_t head = kEfiVarAttributeSize;
  const std::size_t total = content.size();

  while (head < total) {
    if (head + kEslHeaderSize > total) {
      break;
    }

    const uint32_t sig_list_size = readLE32(&data[head + 16]);
    const uint32_t sig_header_size = readLE32(&data[head + 20]);
    const uint32_t sig_size = readLE32(&data[head + 24]);

    // Validate sizes before advancing
    if (sig_list_size == 0 || head + sig_list_size > total) {
      VLOG(1) << "secureboot_certificates: Invalid sig_list_size at offset " << head
              << " in " << path;
      break;
    }

    // Only process X.509 certificate entries; skip hash entries and others.
    if (data[head] != kX509GuidFirstByte) {
      head += sig_list_size;
      continue;
    }

    // Each EFI_SIGNATURE_DATA entry is sig_size bytes, prefixed with a 16-byte
    // owner GUID. Guard against malformed data where sig_size is too small.
    if (sig_size <= kSignatureOwnerGuidSize) {
      head += sig_list_size;
      continue;
    }

    // The signature data area follows the fixed header and optional
    // SignatureHeader.
    const std::size_t sigs_area_offset =
        head + kEslHeaderSize + sig_header_size;
    if (sigs_area_offset > head + sig_list_size) {
      head += sig_list_size;
      continue;
    }

    const std::size_t sigs_area_size =
        (head + sig_list_size) - sigs_area_offset;
    const std::size_t num_sigs = sigs_area_size / sig_size;

    for (std::size_t i = 0; i < num_sigs; ++i) {
      const std::size_t sig_offset = sigs_area_offset + (i * sig_size);
      const std::size_t cert_offset = sig_offset + kSignatureOwnerGuidSize;
      const std::size_t cert_size = sig_size - kSignatureOwnerGuidSize;

      if (cert_offset + cert_size > total) {
        break;
      }

      auto opt_cert_info = parseDerCertificate(&data[cert_offset], cert_size);
      if (!opt_cert_info.has_value()) {
        VLOG(1) << "secureboot_certificates: Failed to parse DER certificate at offset "
                << cert_offset << " in " << path;
        continue;
      }

      const auto& cert_info = opt_cert_info.value();

      Row row;
      row["common_name"] = SQL_TEXT(cert_info.common_name);
      row["subject"] = SQL_TEXT(cert_info.subject);
      row["issuer"] = SQL_TEXT(cert_info.issuer);
      row["not_valid_before"] = INTEGER(cert_info.not_valid_before);
      row["not_valid_after"] = INTEGER(cert_info.not_valid_after);
      row["sha1"] = SQL_TEXT(cert_info.sha1);
      row["serial"] = SQL_TEXT(cert_info.serial);
      row["store"] = SQL_TEXT(store);
      row["path"] = SQL_TEXT(path);
      row["is_ca"] = INTEGER(cert_info.is_ca ? 1 : 0);
      row["self_signed"] = INTEGER(cert_info.is_self_signed ? 1 : 0);
      row["key_usage"] = SQL_TEXT(cert_info.key_usage);
      row["authority_key_id"] = SQL_TEXT(cert_info.authority_key_id);
      row["subject_key_id"] = SQL_TEXT(cert_info.subject_key_id);
      row["signing_algorithm"] = SQL_TEXT(cert_info.signing_algorithm);
      row["key_algorithm"] = SQL_TEXT(cert_info.key_algorithm);
      row["key_strength"] = SQL_TEXT(cert_info.key_strength);

      results.push_back(std::move(row));
    }

    head += sig_list_size;
  }
}

QueryData genSecureBootCertificates(QueryContext& context) {
  QueryData results;

  for (const auto& [glob_pattern, store_name] : kEfiDbGlobs) {
    std::vector<std::string> matching_paths;
    auto status = resolveFilePattern(glob_pattern, matching_paths);
    if (!status.ok() || matching_paths.empty()) {
      continue;
    }

    for (const auto& efi_path : matching_paths) {
      std::string content;
      if (!readFile(efi_path, content).ok()) {
        VLOG(1) << "secureboot_certificates: Cannot open " << efi_path;
        continue;
      }

      if (content.size() <= kEfiVarAttributeSize) {
        continue;
      }

      parseEslData(content, store_name, efi_path, results);
    }
  }

  return results;
}

} // namespace osquery
} // namespace tables
