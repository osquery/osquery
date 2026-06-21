/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Windows.h>
#include <wincrypt.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>
#include <osquery/tables/system/windows/wincert_utils.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/info/firmware.h>

#include <boost/endian/conversion.hpp>
#include <boost/optional.hpp>

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

namespace osquery {
namespace tables {

namespace {
static const std::string kEfiImageSecurityDbGuid =
    "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";

static constexpr std::size_t kEslHeaderSize = 28U;

static constexpr std::size_t kSignatureOwnerGuidSize = 16U;

// First byte of EFI_CERT_X509_GUID as stored on disk in little-endian order.
// EFI_CERT_X509_GUID = {0xa5c059a1, ...} -> disk byte 0 == 0xa1
static constexpr uint8_t kX509GuidFirstByte = 0xa1U;

// Minimum ESL payload size we consider meaningful.
static constexpr std::size_t kMinEslSize = 28U;

// Maximum EFI variable size we will allocate (4 MiB). Prevents unbounded
// buffer growth when GetFirmwareEnvironmentVariableA keeps returning
// ERROR_INSUFFICIENT_BUFFER with a bogus required size.
static constexpr std::size_t kMaxEfiVarSize = 4U * 1024U * 1024U;

using UniqueCertContext =
    std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;

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

// RAII wrapper for a Windows HANDLE that calls CloseHandle on destruction.
struct ScopedHandle {
  explicit ScopedHandle(HANDLE h) : handle(h) {}
  ~ScopedHandle() {
    if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
      CloseHandle(handle);
    }
  }
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  HANDLE handle;
};

bool enableSystemEnvironmentNamePrivilege() {
  TOKEN_PRIVILEGES token_privileges{};
  token_privileges.PrivilegeCount = 1;

  if (!LookupPrivilegeValueW(nullptr,
                             L"SeSystemEnvironmentPrivilege",
                             &token_privileges.Privileges[0].Luid)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to lookup the required privilege: "
               << errorDwordToString(error_code);
    return false;
  }

  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  HANDLE raw_token{INVALID_HANDLE_VALUE};
  if (OpenProcessToken(
          GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw_token) == 0) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to open the process token: "
               << errorDwordToString(error_code);
    return false;
  }
  ScopedHandle process_token(raw_token);

  if (!AdjustTokenPrivileges(process_token.handle,
                             FALSE,
                             &token_privileges,
                             sizeof(TOKEN_PRIVILEGES),
                             nullptr,
                             nullptr)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to adjust token privileges: "
               << errorDwordToString(error_code);
    return false;
  }

  auto error_code = GetLastError();
  if (error_code == ERROR_NOT_ALL_ASSIGNED) {
    LOG(ERROR) << "secureboot: SeSystemEnvironmentPrivilege could not be "
                  "assigned (process may not be running as Administrator). "
                  "EFI variable reads may fail."
               << errorDwordToString(error_code);
    return false;
  }

  return true;
}

} // namespace

boost::optional<EfiCertInfo> parseDerCertificate(const uint8_t* data,
                                                 std::size_t len) {
  UniqueCertContext cert(CertCreateCertificateContext(
                             X509_ASN_ENCODING, data, static_cast<DWORD>(len)),
                         CertFreeCertificateContext);
  if (!cert) {
    return boost::none;
  }

  EfiCertInfo info;
  info.common_name = wstringToString(getCertificateCommonName(cert.get()));
  info.subject = wstringToString(getCertificateSubjectName(cert.get()));
  info.issuer = wstringToString(getCertificateIssuerName(cert.get()));

  info.not_valid_before = getCertificateNotValidBefore(cert.get());
  info.not_valid_after = getCertificateNotValidAfter(cert.get());

  info.sha1 = wstringToString(getCertificateSHA1Digest(cert.get()));
  info.serial = wstringToString(getCertificateSerialNumber(cert.get()));

  info.is_self_signed = isCertificateSelfSigned(cert.get());
  info.is_ca = isCertificateAuthority(cert.get());

  info.key_usage = wstringToString(getCertificateKeyUsage(cert.get()));
  info.authority_key_id =
      wstringToString(getCertificateAuthorityKeyID(cert.get()));
  info.subject_key_id = wstringToString(getCertificateSubjectKeyID(cert.get()));

  info.signing_algorithm =
      wstringToString(getCertificateSigningAlgorithm(cert.get()));
  info.key_algorithm = wstringToString(getCertificateKeyAlgorithm(cert.get()));
  info.key_strength = std::to_string(getCertificateKeyStrength(cert.get()));

  return info;
}

std::string getEfiVariable(std::string namespace_guid,
                           const std::string& db_name) {
  std::vector<BYTE> buffer(65536);
  while (true) {
    DWORD buf_size = static_cast<DWORD>(buffer.size());
    auto status = GetFirmwareEnvironmentVariableA(
        db_name.c_str(), namespace_guid.c_str(), buffer.data(), buf_size);
    if (status > 0) {
      return std::string(buffer.begin(), buffer.begin() + status);
    }
    auto error = GetLastError();
    if (error == ERROR_ENVVAR_NOT_FOUND) {
      LOG(ERROR) << "secureboot_certificates: Unable to get EFI variable "
                 << namespace_guid << "::" << db_name
                 << ". Error: " << errorDwordToString(error);
      return "";
    }
    if (error != ERROR_INSUFFICIENT_BUFFER) {
      LOG(ERROR) << "secureboot_certificates: Unable to get EFI variable "
                 << namespace_guid << "::" << db_name
                 << ". Error: " << errorDwordToString(error);
      return "";
    }
    // Guard against unbounded growth — EFI variables are never legitimately
    // larger than a few megabytes.
    std::size_t next_size = buffer.size() * 2;
    if (next_size > kMaxEfiVarSize) {
      LOG(ERROR) << "secureboot_certificates: EFI variable " << db_name
                 << " exceeds maximum allowed size (" << kMaxEfiVarSize
                 << " bytes). Aborting read.";
      return "";
    }
    buffer.resize(next_size);
  }
}
// Parse a sequence of concatenated EFI_SIGNATURE_LIST structures and add any
// X.509 certificates found to results.
void parseEslData(const std::string& content,
                  bool revoked,
                  const std::string& path,
                  QueryData& results) {
  if (content.size() < kMinEslSize) {
    VLOG(1) << "secureboot_certificates: ESL data too short in " << path;
    return;
  }

  const uint8_t* data = reinterpret_cast<const uint8_t*>(content.data());
  std::size_t head = 0;
  const std::size_t total = content.size();

  while (head < total) {
    if (head + kEslHeaderSize > total) {
      break;
    }

    const uint32_t sig_list_size =
        boost::endian::load_little_u32(&data[head + 16]);
    const uint32_t sig_header_size =
        boost::endian::load_little_u32(&data[head + 20]);
    const uint32_t sig_size = boost::endian::load_little_u32(&data[head + 24]);

    // Validate sizes before advancing
    if (sig_list_size == 0 || head + sig_list_size > total) {
      VLOG(1) << "secureboot_certificates: Invalid sig_list_size at offset "
              << head << " in " << path;
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
        VLOG(1) << "secureboot_certificates: Failed to parse DER certificate "
                   "at offset "
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
      row["revoked"] = INTEGER(revoked ? 1 : 0);
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
  static const auto kPrivilegeInitializationStatus{
      enableSystemEnvironmentNamePrivilege()};

  auto opt_firmware_kind = getFirmwareKind();
  if (!opt_firmware_kind.has_value()) {
    LOG(ERROR) << "secureboot: Failed to determine the firmware type";
    return {};
  }

  const auto& firmware_kind = opt_firmware_kind.value();
  if (firmware_kind != FirmwareKind::Uefi) {
    VLOG(1) << "secureboot: Secure boot is only supported on UEFI firmware";
    return {};
  }

  if (!kPrivilegeInitializationStatus) {
    VLOG(1) << "secureboot: SE_SYSTEM_ENVIRONMENT_NAME privilege was not "
               "acquired. EFI variable reads may fail if not running as "
               "Administrator.";
  }

  for (const auto& search_db : {"db", "dbx"}) {
    auto bytes_read = getEfiVariable(kEfiImageSecurityDbGuid, search_db);
    if (bytes_read.empty()) {
      VLOG(1) << "secureboot_certificates: Skipping empty EFI variable "
              << search_db;
      continue;
    }
    parseEslData(bytes_read, search_db == "dbx", search_db, results);
  }

  return results;
}

} // namespace tables
} // namespace osquery
