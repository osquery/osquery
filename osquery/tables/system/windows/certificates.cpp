/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>
#include <Wintrust.h>
#include <wincrypt.h>

#include <boost/algorithm/hex.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {
namespace tables {

#define CERT_ENCODING (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

const std::map<unsigned long, std::string> kKeyUsages = {
    {CERT_DATA_ENCIPHERMENT_KEY_USAGE, "CERT_DATA_ENCIPHERMENT_KEY_USAGE"},
    {CERT_DIGITAL_SIGNATURE_KEY_USAGE, "CERT_DIGITAL_SIGNATURE_KEY_USAGE"},
    {CERT_KEY_AGREEMENT_KEY_USAGE, "CERT_KEY_AGREEMENT_KEY_USAGE"},
    {CERT_KEY_CERT_SIGN_KEY_USAGE, "CERT_KEY_CERT_SIGN_KEY_USAGE"},
    {CERT_KEY_ENCIPHERMENT_KEY_USAGE, "CERT_KEY_ENCIPHERMENT_KEY_USAGE"},
    {CERT_NON_REPUDIATION_KEY_USAGE, "CERT_NON_REPUDIATION_KEY_USAGE"},
    {CERT_OFFLINE_CRL_SIGN_KEY_USAGE, "CERT_OFFLINE_CRL_SIGN_KEY_USAGE"}};

/// A struct holding the arguments we pass to the WinAPI callback function
typedef struct _ENUM_ARG {
  DWORD dwFlags;
  const void* pvStoreLocationPara;
  QueryData* results;
  std::set<std::string>* processed;
  std::string storeLocation;
} ENUM_ARG, *PENUM_ARG;

std::string cryptOIDToString(const char* objId) {
  if (objId == nullptr) {
    return "";
  }
  auto objKeyId = const_cast<char*>(objId);
  auto oidInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, objKeyId, 0);
  return oidInfo == nullptr ? "" : wstringToString(oidInfo->pwszName);
}

std::string getKeyUsage(const PCERT_INFO& certInfo) {
  // Key usage size is 1 or 2 bytes of data, we use 4 to cast to uint
  constexpr uint32_t keyUsageSize = 4;
  uint32_t keyUsage;
  auto ret = CertGetIntendedKeyUsage(CERT_ENCODING,
                                     certInfo,
                                     reinterpret_cast<BYTE*>(&keyUsage),
                                     keyUsageSize);
  if (ret == 0) {
    return "";
  }
  std::vector<std::string> usages;
  for (const auto& kv : kKeyUsages) {
    if (keyUsage & kv.first) {
      usages.push_back(kv.second);
    }
  }
  return join(usages, ",");
}

void getCertCtxProp(const PCCERT_CONTEXT& certContext,
                    unsigned long propId,
                    std::vector<char>& dataBuff) {
  unsigned long dataBuffLen = 0;
  auto ret = CertGetCertificateContextProperty(
      certContext, propId, nullptr, &dataBuffLen);
  if (ret == 0) {
    VLOG(1) << "Failed to get certificate property structure " << propId
            << " with " << GetLastError();
    return;
  }

  dataBuff.resize(dataBuffLen, 0);
  ret = CertGetCertificateContextProperty(
      certContext, propId, dataBuff.data(), &dataBuffLen);

  if (ret == 0) {
    VLOG(1) << "Failed to get certificate property structure " << propId
            << " with " << GetLastError();
  }
}

/// Enumerate and process a certificate store
void enumerateCertStore(const HCERTSTORE& certStore,
                        const std::string& certStoreName,
                        const std::string& storeLocation,
                        std::set<std::string>& processedCerts,
                        QueryData& results) {
  auto certContext = CertEnumCertificatesInStore(certStore, nullptr);
  if (certContext == nullptr) {
    VLOG(1) << "Failed to enumerate certstore " << storeLocation << "\\"
            << certStoreName << " with " << GetLastError();
    return;
  }

  while (certContext != nullptr) {
    // Get the cert fingerprint and ensure we haven't already processed it
    std::vector<char> certBuff;
    getCertCtxProp(certContext, CERT_HASH_PROP_ID, certBuff);
    std::string fingerprint;
    boost::algorithm::hex(std::string(certBuff.begin(), certBuff.end()),
                          back_inserter(fingerprint));

    if (processedCerts.find(fingerprint) != processedCerts.end()) {
      certContext = CertEnumCertificatesInStore(certStore, certContext);
      continue;
    }
    processedCerts.insert(fingerprint);

    Row r;
    r["sha1"] = fingerprint;
    certBuff.resize(256, 0);
    std::fill(certBuff.begin(), certBuff.end(), 0);
    CertGetNameString(certContext,
                      CERT_NAME_SIMPLE_DISPLAY_TYPE,
                      0,
                      nullptr,
                      certBuff.data(),
                      static_cast<unsigned long>(certBuff.size()));
    r["common_name"] = certBuff.data();

    auto subjSize = CertNameToStr(certContext->dwCertEncodingType,
                                  &(certContext->pCertInfo->Subject),
                                  CERT_SIMPLE_NAME_STR,
                                  nullptr,
                                  0);
    certBuff.resize(subjSize, 0);
    std::fill(certBuff.begin(), certBuff.end(), 0);
    subjSize = CertNameToStr(certContext->dwCertEncodingType,
                             &(certContext->pCertInfo->Subject),
                             CERT_SIMPLE_NAME_STR,
                             certBuff.data(),
                             subjSize);
    r["subject"] = subjSize == 0 ? "" : certBuff.data();

    auto issuerSize = CertNameToStr(certContext->dwCertEncodingType,
                                    &(certContext->pCertInfo->Issuer),
                                    CERT_SIMPLE_NAME_STR,
                                    nullptr,
                                    0);
    certBuff.resize(issuerSize, 0);
    std::fill(certBuff.begin(), certBuff.end(), 0);
    issuerSize = CertNameToStr(certContext->dwCertEncodingType,
                               &(certContext->pCertInfo->Issuer),
                               CERT_SIMPLE_NAME_STR,
                               certBuff.data(),
                               issuerSize);
    r["issuer"] = issuerSize == 0 ? "" : certBuff.data();

    // TODO: Find the right API calls to get whether a cert is for a CA
    r["ca"] = INTEGER(-1);

    r["self_signed"] =
        WTHelperCertIsSelfSigned(CERT_ENCODING, certContext->pCertInfo)
            ? INTEGER(1)
            : INTEGER(0);

    r["not_valid_before"] =
        INTEGER(filetimeToUnixtime(certContext->pCertInfo->NotBefore));

    r["not_valid_after"] =
        INTEGER(filetimeToUnixtime(certContext->pCertInfo->NotAfter));

    r["signing_algorithm"] =
        cryptOIDToString(certContext->pCertInfo->SignatureAlgorithm.pszObjId);

    r["key_algorithm"] = cryptOIDToString(
        certContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

    r["key_usage"] = getKeyUsage(certContext->pCertInfo);

    r["key_strength"] = INTEGER((certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData) * 8);

    certBuff.clear();
    getCertCtxProp(certContext, CERT_KEY_IDENTIFIER_PROP_ID, certBuff);
    std::string subjectKeyId;
    boost::algorithm::hex(std::string(certBuff.begin(), certBuff.end()),
                          back_inserter(subjectKeyId));
    r["subject_key_id"] = subjectKeyId;

    r["path"] = storeLocation + "\\" + certStoreName;

    std::string serial;
    boost::algorithm::hex(
        std::string(certContext->pCertInfo->SerialNumber.pbData,
                    certContext->pCertInfo->SerialNumber.pbData +
                        certContext->pCertInfo->SerialNumber.cbData),
        back_inserter(serial));
    r["serial"] = serial;

    std::string authKeyId;
    if (certContext->pCertInfo->cExtension != 0) {
      auto extension = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
                                         certContext->pCertInfo->cExtension,
                                         certContext->pCertInfo->rgExtension);
      if (extension != nullptr) {
        unsigned long decodedBuffSize = 0;
        CryptDecodeObjectEx(CERT_ENCODING,
                            X509_AUTHORITY_KEY_ID2,
                            extension->Value.pbData,
                            extension->Value.cbData,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            nullptr,
                            nullptr,
                            &decodedBuffSize);

        certBuff.resize(decodedBuffSize, 0);
        std::fill(certBuff.begin(), certBuff.end(), 0);
        auto decodeRet = CryptDecodeObjectEx(CERT_ENCODING,
                                             X509_AUTHORITY_KEY_ID2,
                                             extension->Value.pbData,
                                             extension->Value.cbData,
                                             CRYPT_DECODE_NOCOPY_FLAG,
                                             nullptr,
                                             certBuff.data(),
                                             &decodedBuffSize);
        if (decodeRet != FALSE) {
          auto authKeyIdBlob =
              reinterpret_cast<CERT_AUTHORITY_KEY_ID2_INFO*>(certBuff.data());

          boost::algorithm::hex(std::string(authKeyIdBlob->KeyId.pbData,
                                            authKeyIdBlob->KeyId.pbData +
                                                authKeyIdBlob->KeyId.cbData),
                                back_inserter(authKeyId));
        } else {
          VLOG(1) << "Failed to decode authority_key_id with ("
                  << GetLastError() << ")";
        }
      }
    }
    r["authority_key_id"] = authKeyId;

    results.push_back(r);
    certContext = CertEnumCertificatesInStore(certStore, certContext);
  }
}

/// Windows API callback for processing a system cert store
BOOL WINAPI certEnumSystemStoreCallback(const void* systemStore,
                                        unsigned long flags,
                                        PCERT_SYSTEM_STORE_INFO storeInfo,
                                        void* reserved,
                                        void* arg) {
  auto* storeArg = static_cast<ENUM_ARG*>(arg);
  const auto& certStoreName =
      wstringToString(static_cast<LPCWSTR>(systemStore));
  const auto& friendlyStoreName = wstringToString(
      CryptFindLocalizedName(static_cast<LPCWSTR>(systemStore)));
  auto certHandle = CertOpenSystemStore(0, certStoreName.c_str());
  if (certHandle == nullptr) {
    VLOG(1) << "Failed to open cert store " << certStoreName << " with "
            << GetLastError();
    return FALSE;
  }

  enumerateCertStore(certHandle,
                     friendlyStoreName,
                     storeArg->storeLocation,
                     *storeArg->processed,
                     *storeArg->results);

  auto ret = CertCloseStore(certHandle, 0);
  if (ret != TRUE) {
    VLOG(1) << "Closing cert store failed with " << GetLastError();
    return FALSE;
  }
  return TRUE;
}

/// Windows API callback for processing a system cert store location
BOOL WINAPI certEnumSystemStoreLocationsCallback(LPCWSTR storeLocation,
                                                 unsigned long flags,
                                                 void* reserved,
                                                 void* arg) {
  auto enumArg = static_cast<PENUM_ARG>(arg);
  enumArg->storeLocation = wstringToString(storeLocation);
  flags &= CERT_SYSTEM_STORE_MASK;
  flags |= enumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
  auto ret =
      CertEnumSystemStore(flags,
                          const_cast<void*>(enumArg->pvStoreLocationPara),
                          enumArg,
                          certEnumSystemStoreCallback);

  if (ret != 1) {
    VLOG(1) << "Failed to enumerate " << enumArg->storeLocation
            << " store with " << GetLastError();
    return FALSE;
  }
  return TRUE;
}

QueryData genCerts(QueryContext& context) {
  QueryData results;
  std::set<std::string> processedCerts;
  ENUM_ARG enumArg;

  unsigned long flags = 0;
  DWORD locationId = CERT_SYSTEM_STORE_CURRENT_USER_ID;

  enumArg.dwFlags = flags;
  enumArg.pvStoreLocationPara = nullptr;
  enumArg.results = &results;
  enumArg.processed = &processedCerts;

  flags &= ~CERT_SYSTEM_STORE_LOCATION_MASK;
  flags |= (locationId << CERT_SYSTEM_STORE_LOCATION_SHIFT) &
           CERT_SYSTEM_STORE_LOCATION_MASK;

  auto ret = CertEnumSystemStoreLocation(
      flags, &enumArg, certEnumSystemStoreLocationsCallback);

  if (ret != 1) {
    VLOG(1) << "Failed to enumerate system store locations with "
            << GetLastError();
    return results;
  }

  return results;
}
} // namespace tables
} // namespace osquery
