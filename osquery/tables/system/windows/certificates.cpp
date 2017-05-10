/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>

#include <boost/algorithm/hex.hpp>

#include <osquery/database.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/logger.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

#define CERT_ENCODING (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

struct certStoreLocation {
  unsigned long storeId;
  std::wstring storeName;
};

typedef struct _ENUM_ARG {
  BOOL fAll;
  BOOL fVerbose;
  DWORD dwFlags;
  const void* pvStoreLocationPara;
  HKEY hKeyBase;
  QueryData* results;
} ENUM_ARG, *PENUM_ARG;

typedef std::vector<certStoreLocation> storeLocationsContainer;
typedef std::vector<ENUM_ARG> storeContainer;

void enumerateCertStore(const HCERTSTORE& certStore, QueryData& results) {
  PCCERT_CONTEXT certContext = nullptr;
  certContext = CertEnumCertificatesInStore(certStore, certContext);
  if (certContext == nullptr) {
    VLOG(1) << "Failed to enumerate certificates certstore with "
            << GetLastError();
    return;
  }

  while (certContext != nullptr) {
    Row r;
    std::vector<char> certName(256, 0x0);
    auto ret = CertGetNameString(certContext,
                                 CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                 0x0,
                                 nullptr,
                                 certName.data(),
                                 static_cast<unsigned long>(certName.size()));
    r["common_name"] = certName.data();
    unsigned long propId = 0;
    // propId = CertEnumCertificateContextProperties(certContext, propId);

    unsigned long dataBuffLen = 0;

    auto certPropRet = CertGetCertificateContextProperty(
        certContext, CERT_HASH_PROP_ID, nullptr, &dataBuffLen);
    std::vector<char> dataBuff(dataBuffLen, 0x0);
    ret = CertGetCertificateContextProperty(
        certContext, CERT_HASH_PROP_ID, dataBuff.data(), &dataBuffLen);

    std::stringstream hexSha1;
    try {
      boost::algorithm::hex(dataBuff.data(),
                            std::ostream_iterator<char>{hexSha1, ""});
    } catch (std::exception /* e */) { }
    r["sha1"] = hexSha1.str();

    auto subjSize = CertNameToStr(certContext->dwCertEncodingType,
                                  &(certContext->pCertInfo->Subject),
                                  CERT_OID_NAME_STR,
                                  nullptr,
                                  0);

    std::vector<char> subject(subjSize, 0x0);
    subjSize = CertNameToStr(certContext->dwCertEncodingType,
                             &(certContext->pCertInfo->Subject),
                             CERT_OID_NAME_STR,
                             subject.data(),
                             subjSize);

    r["subject"] = subjSize == 0 ? "" : std::string(subject.data());

    auto issuerSize = CertNameToStr(certContext->dwCertEncodingType,
                                    &(certContext->pCertInfo->Issuer),
                                    CERT_OID_NAME_STR,
                                    nullptr,
                                    0);

    std::vector<char> issuer(issuerSize, 0x0);
    issuerSize = CertNameToStr(certContext->dwCertEncodingType,
                               &(certContext->pCertInfo->Issuer),
                               CERT_OID_NAME_STR,
                               issuer.data(),
                               issuerSize);

    r["issuer"] = issuerSize == 0 ? "" : std::string(issuer.data());

    r["ca"] = INTEGER(-1);

    r["self_signed"] = INTEGER(-1);

    r["not_valid_before"] =
        std::to_string(filetimeToUnixtime(certContext->pCertInfo->NotBefore));

    r["not_valid_after"] =
        std::to_string(filetimeToUnixtime(certContext->pCertInfo->NotAfter));

    r["signing_algorithm"] = "";

    r["key_algorithm"] =
        certContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;

    r["key_usage"] = "";

    r["key_strength"] = INTEGER(certContext->cbCertEncoded);

    std::stringstream subjId;
    if (certContext->pCertInfo->SubjectUniqueId.cbData > 0) {
      try {
        boost::algorithm::hex(certContext->pCertInfo->SubjectUniqueId.pbData,
                              std::ostream_iterator<char>{subjId, ""});
      } catch (std::exception /* e */) {
      }
      r["subject_key_id"] = subjId.str();
    } else {
      r["subject_key_id"] = "";
    }

    std::stringstream issuerId;
    if (certContext->pCertInfo->IssuerUniqueId.cbData > 0) {
      try {
        boost::algorithm::hex(certContext->pCertInfo->IssuerUniqueId.pbData,
                              std::ostream_iterator<char>{issuerId, ""});
      } catch (std::exception /* e */) {
      }
      r["authority_key_id"] = issuerId.str();
    } else {
      r["authority_key_id"] = "";
    }

    r["path"] = "";

    results.push_back(r);
    certContext = CertEnumCertificatesInStore(certStore, certContext);
  }
}

// Windows API callback for processing a system cert store
BOOL WINAPI certEnumSystemStoreCallback(const void* systemStore,
                                        unsigned long flags,
                                        PCERT_SYSTEM_STORE_INFO storeInfo,
                                        void* reserved,
                                        void* arg) {
  ENUM_ARG& storeArg = *static_cast<ENUM_ARG*>(arg);

  auto certStoreName = wstringToString(static_cast<LPCWSTR>(systemStore));
  auto certHandle = CertOpenSystemStore(0x0, certStoreName.c_str());
  if (certHandle == nullptr) {
    VLOG(1) << "Failed to open cert store " << certStoreName << " with "
            << GetLastError();
    return FALSE;
  }
  enumerateCertStore(certHandle, *(storeArg.results));

  auto ret = CertCloseStore(certHandle, 0x0);
  if (ret != TRUE) {
    VLOG(1) << "Closing cert store failed with " << GetLastError();
    return FALSE;
  }

  return TRUE;
}

// Windows API callback for processing a system cert store location
BOOL WINAPI certEnumSystemStoreLocationsCallback(LPCWSTR storeLocation,
                                                 unsigned long flags,
                                                 void* reserved,
                                                 void* arg) {
  PENUM_ARG enumArg = static_cast<PENUM_ARG>(arg);

  flags &= CERT_SYSTEM_STORE_MASK;
  flags |= enumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
  auto ret = CertEnumSystemStore(flags,
                                 (void*)enumArg->pvStoreLocationPara,
                                 enumArg,
                                 certEnumSystemStoreCallback);

  if (ret != 1) {
    VLOG(1) << "Failed to enumerate system stores with " << GetLastError();
    return FALSE;
  }

  return TRUE;
}

QueryData genCerts(QueryContext& context) {
  QueryData results;

  storeLocationsContainer certStoreLocations;
  unsigned long flags = 0;
  ENUM_ARG enumArg;
  HKEY hKeyBase = nullptr;
  LPWSTR pwszStoreLocationPara = nullptr;
  void* storeLocationPara = pwszStoreLocationPara;
  DWORD locationId = CERT_SYSTEM_STORE_CURRENT_USER_ID; // TODO: Wat.

  enumArg.dwFlags = flags;
  enumArg.hKeyBase = hKeyBase;

  enumArg.pvStoreLocationPara = storeLocationPara;
  enumArg.fAll = TRUE;
  enumArg.results = &results;

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
