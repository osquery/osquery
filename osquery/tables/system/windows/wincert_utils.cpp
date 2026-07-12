/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/windows/wincert_utils.h>

#include <map>

#include <Wintrust.h>

#include <boost/algorithm/string/join.hpp>

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {
namespace tables {

namespace {

static constexpr DWORD kCertEncoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

const std::map<unsigned long, std::wstring> kKeyUsages = {
    {CERT_DATA_ENCIPHERMENT_KEY_USAGE, L"Data Encipherment"},
    {CERT_DIGITAL_SIGNATURE_KEY_USAGE, L"Digital Signature"},
    {CERT_KEY_AGREEMENT_KEY_USAGE, L"Key Agreement"},
    {CERT_KEY_CERT_SIGN_KEY_USAGE, L"Key Cert Sign"},
    {CERT_KEY_ENCIPHERMENT_KEY_USAGE, L"Key Encipherment"},
    {CERT_NON_REPUDIATION_KEY_USAGE, L"Non Repudiation"},
    {CERT_OFFLINE_CRL_SIGN_KEY_USAGE, L"CRL Sign"}};

/**
 * @brief Helper to convert a name blob to a wide string.
 */
std::wstring getCertNameToStr(const CERT_NAME_BLOB& name_blob, DWORD type) {
  auto len = CertNameToStrW(
      kCertEncoding, const_cast<PCERT_NAME_BLOB>(&name_blob), type, nullptr, 0);
  if (len <= 1) {
    return {};
  }
  std::vector<WCHAR> certName(len);
  CertNameToStrW(kCertEncoding,
                 const_cast<PCERT_NAME_BLOB>(&name_blob),
                 type,
                 certName.data(),
                 len);
  return std::wstring(certName.data());
}

/**
 * @brief Decodes a certificate extension into a raw buffer.
 */
bool decodeCertificateExtension(PCCERT_CONTEXT certContext,
                                const char* oid,
                                const char* structType,
                                std::vector<BYTE>& buffer) {
  auto extension = CertFindExtension(oid,
                                     certContext->pCertInfo->cExtension,
                                     certContext->pCertInfo->rgExtension);
  if (extension == nullptr) {
    return false;
  }

  DWORD decodedLen = 0;
  if (!CryptDecodeObjectEx(kCertEncoding,
                           structType,
                           extension->Value.pbData,
                           extension->Value.cbData,
                           0,
                           nullptr,
                           nullptr,
                           &decodedLen)) {
    return false;
  }

  buffer.resize(decodedLen);
  return CryptDecodeObjectEx(kCertEncoding,
                             structType,
                             extension->Value.pbData,
                             extension->Value.cbData,
                             0,
                             nullptr,
                             buffer.data(),
                             &decodedLen);
}

std::wstring cryptOIDToString(const char* objId) {
  if (objId == nullptr) {
    return {};
  }
  auto oidInfo =
      CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, const_cast<char*>(objId), 0);
  return oidInfo ? oidInfo->pwszName : L"";
}

} // namespace

std::wstring getCertificateSubjectName(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  return getCertNameToStr(certContext->pCertInfo->Subject,
                          CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG);
}

std::wstring getCertificateIssuerName(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  return getCertNameToStr(certContext->pCertInfo->Issuer,
                          CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG);
}

std::wstring getCertificateCommonName(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr) {
    return {};
  }
  DWORD len = CertGetNameStringW(
      certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  if (len <= 1) {
    return {};
  }
  std::vector<WCHAR> name(len);
  CertGetNameStringW(
      certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), len);
  return std::wstring(name.data());
}

std::wstring getCertificateSerialNumber(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  std::string serial;
  toHexStr(certContext->pCertInfo->SerialNumber.pbData,
           certContext->pCertInfo->SerialNumber.pbData +
               certContext->pCertInfo->SerialNumber.cbData,
           serial,
           true);
  return stringToWstring(serial);
}

std::wstring getCertificateSHA1Digest(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr) {
    return {};
  }
  std::vector<BYTE> hash;
  unsigned long hashLen = 0;
  if (!CertGetCertificateContextProperty(
          certContext, CERT_HASH_PROP_ID, nullptr, &hashLen)) {
    return {};
  }
  hash.resize(hashLen);
  if (!CertGetCertificateContextProperty(
          certContext, CERT_HASH_PROP_ID, hash.data(), &hashLen)) {
    return {};
  }
  std::string digest;
  toHexStr(hash.begin(), hash.end(), digest);
  return stringToWstring(digest);
}

bool isCertificateAuthority(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return false;
  }
  std::vector<BYTE> buffer;
  if (decodeCertificateExtension(certContext,
                                 szOID_BASIC_CONSTRAINTS2,
                                 X509_BASIC_CONSTRAINTS2,
                                 buffer)) {
    auto constraints =
        reinterpret_cast<PCERT_BASIC_CONSTRAINTS2_INFO>(buffer.data());
    return constraints->fCA != FALSE;
  }
  return false;
}

bool isCertificateSelfSigned(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return false;
  }
  return WTHelperCertIsSelfSigned(kCertEncoding, certContext->pCertInfo) !=
         FALSE;
}

std::wstring getCertificateKeyUsage(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  uint32_t usage = 0;
  if (!CertGetIntendedKeyUsage(kCertEncoding,
                               certContext->pCertInfo,
                               reinterpret_cast<BYTE*>(&usage),
                               4)) {
    return {};
  }
  std::vector<std::wstring> results;
  for (const auto& kv : kKeyUsages) {
    if (usage & kv.first) {
      results.push_back(kv.second);
    }
  }
  return boost::algorithm::join(results, L", ");
}

std::wstring getCertificateSigningAlgorithm(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  return cryptOIDToString(certContext->pCertInfo->SignatureAlgorithm.pszObjId);
}

std::wstring getCertificateKeyAlgorithm(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  return cryptOIDToString(
      certContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
}

DWORD getCertificateKeyStrength(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return 0;
  }
  return CertGetPublicKeyLength(kCertEncoding,
                                &certContext->pCertInfo->SubjectPublicKeyInfo);
}

std::time_t getCertificateNotValidBefore(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return 0;
  }
  return static_cast<std::time_t>(
      filetimeToUnixtime(certContext->pCertInfo->NotBefore));
}

std::time_t getCertificateNotValidAfter(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return 0;
  }
  return static_cast<std::time_t>(
      filetimeToUnixtime(certContext->pCertInfo->NotAfter));
}

std::wstring getCertificateAuthorityKeyID(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  std::vector<BYTE> buffer;
  if (decodeCertificateExtension(certContext,
                                 szOID_AUTHORITY_KEY_IDENTIFIER2,
                                 X509_AUTHORITY_KEY_ID2,
                                 buffer)) {
    auto authKeyId =
        reinterpret_cast<PCERT_AUTHORITY_KEY_ID2_INFO>(buffer.data());
    if (authKeyId->KeyId.cbData > 0) {
      std::string keyId;
      toHexStr(authKeyId->KeyId.pbData,
               authKeyId->KeyId.pbData + authKeyId->KeyId.cbData,
               keyId);
      return stringToWstring(keyId);
    }
  }
  return {};
}

std::wstring getCertificateSubjectKeyID(PCCERT_CONTEXT certContext) {
  if (certContext == nullptr || certContext->pCertInfo == nullptr) {
    return {};
  }
  std::vector<BYTE> buffer;
  if (decodeCertificateExtension(certContext,
                                 szOID_SUBJECT_KEY_IDENTIFIER,
                                 X509_OCTET_STRING,
                                 buffer)) {
    auto keyId = reinterpret_cast<PCRYPT_DATA_BLOB>(buffer.data());
    if (keyId->cbData > 0) {
      std::string skid;
      toHexStr(keyId->pbData, keyId->pbData + keyId->cbData, skid);
      return stringToWstring(skid);
    }
  }
  return {};
}

} // namespace tables
} // namespace osquery
