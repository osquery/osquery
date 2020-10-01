/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <codecvt>
#include <map>
#include <string>

// clang-format off
#include <osquery/utils/system/system.h>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <mscat.h>
#include <iomanip>
// clang-format on

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/core/tables.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
template <typename T, typename DeleterType, DeleterType deleter>
struct CustomUniquePtr final {
  using pointer = T;
  using deleter_type = CustomUniquePtr<T, DeleterType, deleter>;
  using type = std::unique_ptr<T, deleter_type>;

  void operator()(pointer p) {
    deleter(p);
  }
};

void CertStoreDeleter(HCERTSTORE h) {
  CertCloseStore(h, 0);
}

using unique_hcertstore =
    CustomUniquePtr<HCERTSTORE, decltype(&CertStoreDeleter), CertStoreDeleter>;

using unique_certcontext =
    CustomUniquePtr<PCCERT_CONTEXT,
                    decltype(&CertFreeCertificateContext),
                    CertFreeCertificateContext>;

using unique_hcryptmsg =
    CustomUniquePtr<HCRYPTMSG, decltype(&CryptMsgClose), CryptMsgClose>;

struct SignatureInformation final {
  enum class Result { Valid, Trusted, Invalid, Missing, Distrusted, Untrusted };

  /// Executable path
  std::string path;

  /// The original program name, when the publisher has signed the program
  std::string original_program_name;

  /// Serial number
  std::string serial_number;

  /// Issuer name
  std::string issuer_name;

  /// The subject name
  std::string subject_name;

  /// Signature verification result
  Result result;
};

void generateRow(Row& row, const SignatureInformation& signature_info) {
  row.clear();

  row["path"] = signature_info.path;
  row["serial_number"] = signature_info.serial_number;
  row["issuer_name"] = signature_info.issuer_name;
  row["subject_name"] = signature_info.subject_name;
  row["original_program_name"] = signature_info.original_program_name;

  switch (signature_info.result) {
  case SignatureInformation::Result::Valid: {
    row["result"] = "valid";
    break;
  }

  case SignatureInformation::Result::Trusted: {
    row["result"] = "trusted";
    break;
  }

  case SignatureInformation::Result::Invalid: {
    row["result"] = "invalid";
    break;
  }

  case SignatureInformation::Result::Missing: {
    row["result"] = "missing";
    break;
  }

  case SignatureInformation::Result::Distrusted: {
    row["result"] = "distrusted";
    break;
  }

  case SignatureInformation::Result::Untrusted: {
    row["result"] = "untrusted";
    break;
  }

  default: {
    row["result"] = "unknown";
    LOG(ERROR) << "Unexpected result value";
    break;
  }
  }
}

bool getCatalogPathForFilePath(const std::wstring& path,
                               std::wstring& catalogFile) {
  bool status = false;
  HANDLE handle = CreateFile(path.c_str(),
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
  if (handle != INVALID_HANDLE_VALUE) {
    HCATADMIN context;
    GUID subsystem = DRIVER_ACTION_VERIFY;
    HCATINFO catalog = NULL;

    const SIZE_T SHA512_HASH_SIZE = 64;
    BYTE hash[SHA512_HASH_SIZE];
    DWORD hash_size = ARRAYSIZE(hash);

    if (CryptCATAdminAcquireContext(&context, &subsystem, NULL)) {
      if (CryptCATAdminCalcHashFromFileHandle(handle, &hash_size, hash, 0)) {
        catalog =
            CryptCATAdminEnumCatalogFromHash(context, hash, hash_size, 0, NULL);
        if (NULL != catalog) {
          CATALOG_INFO info = {0};
          info.cbStruct = sizeof(info);
          if (CryptCATCatalogInfoFromContext(catalog, &info, 0)) {
            catalogFile = info.wszCatalogFile;
            status = true;
          }

          CryptCATAdminReleaseCatalogContext(context, catalog, 0);
        }
      }
      CryptCATAdminReleaseContext(context, 0);
    }

    CloseHandle(handle);
  }

  return status;
}

Status verifySignature(SignatureInformation::Result& result,
                       const std::wstring& path) {
  WINTRUST_DATA trust_provider_settings = {};
  trust_provider_settings.cbStruct = sizeof(WINTRUST_DATA);

  // Set the input file
  WINTRUST_FILE_INFO file_info = {};
  file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
  file_info.pcwszFilePath = path.data();
  trust_provider_settings.pFile = &file_info;

  // Do revocation checking
  trust_provider_settings.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;

  // Disable the UI
  trust_provider_settings.dwUIChoice = WTD_UI_NONE;

  // Verify an embedded signature
  trust_provider_settings.dwStateAction = WTD_STATEACTION_VERIFY;
  trust_provider_settings.dwUnionChoice = WTD_CHOICE_FILE;

  // Do the actual verification
  GUID authenticode_policy_provider = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  auto verification_status =
      WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                     &authenticode_policy_provider,
                     &trust_provider_settings);

  bool verification_error = false;

  switch (verification_status) {
  // Signatures that have been distrusted by the administrator
  case TRUST_E_EXPLICIT_DISTRUST: {
    result = SignatureInformation::Result::Distrusted;
    break;
  }

  // There may be no signature, but we also end up here if the file is malformed
  // or not accessible.
  case TRUST_E_NOSIGNATURE: {
    auto error_code = GetLastError();
    if (error_code != TRUST_E_NOSIGNATURE &&
        error_code != TRUST_E_SUBJECT_FORM_UNKNOWN &&
        error_code != TRUST_E_PROVIDER_UNKNOWN) {
      verification_error = true;
      break;
    }

    result = SignatureInformation::Result::Missing;
    break;
  }

  case ERROR_SUCCESS: {
    result = SignatureInformation::Result::Trusted;
    break;
  }

  // Although this signature is perfectly valid, it wasn't explicitly trusted
  // by the system administrator
  case CRYPT_E_SECURITY_SETTINGS: {
    result = SignatureInformation::Result::Valid;
    break;
  }

  case TRUST_E_SUBJECT_NOT_TRUSTED:
  default: {
    result = SignatureInformation::Result::Untrusted;
    break;
  }
  }

  trust_provider_settings.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                 &authenticode_policy_provider,
                 &trust_provider_settings);

  if (verification_error) {
    return Status(1, "Failed to verify the file signature");
  }

  return Status::success();
}

Status getOriginalProgramName(SignatureInformation& signature_info,
                              PCMSG_SIGNER_INFO signer_info) {
  PCRYPT_ATTRIBUTE publisher_info_ptr = nullptr;

  for (DWORD i = 0; i < signer_info->AuthAttrs.cAttr; i++) {
    if (std::strcmp(SPC_SP_OPUS_INFO_OBJID,
                    signer_info->AuthAttrs.rgAttr[i].pszObjId) == 0) {
      publisher_info_ptr = &signer_info->AuthAttrs.rgAttr[i];
      break;
    }
  }

  if (publisher_info_ptr == nullptr) {
    return Status(1, "The publisher information could not be found");
  }

  DWORD publisher_info_size;
  if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                         SPC_SP_OPUS_INFO_OBJID,
                         publisher_info_ptr->rgValue[0].pbData,
                         publisher_info_ptr->rgValue[0].cbData,
                         0,
                         nullptr,
                         &publisher_info_size)) {
    return Status(1, "Failed to access the publisher information");
  }

  std::vector<std::uint8_t> publisher_info_blob_buffer(
      static_cast<std::size_t>(publisher_info_size));

  PSPC_SP_OPUS_INFO publisher_info_blob_ptr =
      reinterpret_cast<PSPC_SP_OPUS_INFO>(publisher_info_blob_buffer.data());

  if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                         SPC_SP_OPUS_INFO_OBJID,
                         publisher_info_ptr->rgValue[0].pbData,
                         publisher_info_ptr->rgValue[0].cbData,
                         0,
                         publisher_info_ptr,
                         &publisher_info_size)) {
    return Status(1, "Failed to decode the publisher information");
  }

  if (publisher_info_blob_ptr->pwszProgramName != nullptr) {
    signature_info.original_program_name =
        wstringToString(publisher_info_blob_ptr->pwszProgramName);
  }

  return Status::success();
}

Status getCertificateInformation(SignatureInformation& signature_info,
                                 PCCERT_CONTEXT certificate_context) {
  PCRYPT_INTEGER_BLOB serial_number =
      &certificate_context->pCertInfo->SerialNumber;

  std::stringstream serial_number_string;
  for (DWORD i = serial_number->cbData - 1; i < serial_number->cbData; i--) {
    serial_number_string << std::hex << std::setfill('0') << std::setw(2)
                         << static_cast<int>(serial_number->pbData[i]);
  }

  signature_info.serial_number = serial_number_string.str();

  auto L_GetCertificateDetail = [](std::string& value,
                                   PCCERT_CONTEXT certificate_context,
                                   DWORD detail) -> bool {
    DWORD value_size = CertGetNameStringW(certificate_context,
                                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                          detail,
                                          nullptr,
                                          nullptr,
                                          0);
    if (value_size == 0U || value_size >= 10000) {
      VLOG(1) << "Invalid certificate field size: " << value_size;
      return false;
    }

    std::wstring buffer(static_cast<std::size_t>(value_size), 0);

    if (!CertGetNameStringW(certificate_context,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            detail,
                            nullptr,
                            &buffer[0],
                            value_size)) {
      return false;
    }

    value = wstringToString(buffer.c_str());
    return true;
  };

  if (!L_GetCertificateDetail(signature_info.issuer_name,
                              certificate_context,
                              CERT_NAME_ISSUER_FLAG)) {
    return Status(1, "Failed to retrieve the issuer name");
  }

  if (!L_GetCertificateDetail(
          signature_info.subject_name, certificate_context, 0)) {
    return Status::failure("Failed to retrieve the subject name");
  }

  return Status::success();
}

Status getSignatureInformation(SignatureInformation& signature_info,
                               const std::wstring& path) {
  unique_hcryptmsg::type message;
  unique_hcertstore::type certificate_store;

  {
    HCERTSTORE certificate_store_handle;
    HCRYPTMSG message_handle;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                          path.data(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0,
                          nullptr,
                          nullptr,
                          nullptr,
                          &certificate_store_handle,
                          &message_handle,
                          nullptr)) {
      return Status(1,
                    "Failed to query the Authenticode signature information");
    }

    certificate_store.reset(certificate_store_handle);
    message.reset(message_handle);
  }

  DWORD signer_info_size;
  if (!CryptMsgGetParam(message.get(),
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        nullptr,
                        &signer_info_size)) {
    return Status(1, "Failed to get the signer information size");
  }

  std::vector<std::uint8_t> signer_information(
      static_cast<std::size_t>(signer_info_size));

  PCMSG_SIGNER_INFO signer_information_ptr =
      reinterpret_cast<PCMSG_SIGNER_INFO>(signer_information.data());
  if (!CryptMsgGetParam(message.get(),
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        signer_information_ptr,
                        &signer_info_size)) {
    return Status(1, "Failed to acquire the signer information");
  }

  auto status = getOriginalProgramName(signature_info, signer_information_ptr);
  if (!status.ok()) {
    return status;
  }

  unique_certcontext::type certificate_context;

  {
    CERT_INFO cert_search_params = {};
    cert_search_params.Issuer = signer_information_ptr->Issuer;
    cert_search_params.SerialNumber = signer_information_ptr->SerialNumber;

    auto cert_context =
        CertFindCertificateInStore(certificate_store.get(),
                                   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                   0,
                                   CERT_FIND_SUBJECT_CERT,
                                   &cert_search_params,
                                   nullptr);
    if (!cert_context) {
      return Status(1, "Lookup failed in the temporary certificate store");
    }

    certificate_context.reset(cert_context);
  }

  status = getCertificateInformation(signature_info, certificate_context.get());
  if (!status.ok()) {
    return status;
  }

  return Status::success();
}

Status querySignatureInformation(SignatureInformation& signature_info,
                                 const std::string& path) {
  signature_info = {};

  std::wstring utf16_path = stringToWstring(path);
  if (utf16_path.empty()) {
    return Status(1, "Invalid path");
  }

  signature_info.path = path;

  std::wstring catalog;
  // may be a system file whose hash is in the catalog file.
  // if so, return the catalog's signature instead.
  if (getCatalogPathForFilePath(utf16_path, catalog)) {
    utf16_path = catalog;
  }

  auto status = verifySignature(signature_info.result, utf16_path);
  if (!status.ok()) {
    return status;
  }

  if (signature_info.result == SignatureInformation::Result::Missing) {
    return Status::success();
  }

  status = getSignatureInformation(signature_info, utf16_path);
  if (!status.ok()) {
    return status;
  }

  return Status::success();
}

namespace tables {
Status generateRow(Row& r, const std::string& path) {
  r = {};

  SignatureInformation signature_info;
  auto status = querySignatureInformation(signature_info, path);
  if (!status.ok()) {
    std::stringstream error_message;
    error_message << "Failed to verify the Authenticode signature for the "
                     "following file: "
                  << path << ". Error: " << status.getMessage();

    return Status(1, error_message.str());
  }

  generateRow(r, signature_info);
  return Status::success();
}

QueryData genAuthenticode(QueryContext& context) {
  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
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

  QueryData results;
  for (const auto& path_string : paths) {
    if (path_string.empty()) {
      LOG(WARNING) << "Empty path received";
      continue;
    }

    Row r;
    auto status = generateRow(r, path_string);
    if (status.ok()) {
      results.push_back(r);
    } else {
      LOG(WARNING) << status.getMessage();
    }
  }

  return results;
}
}
}
