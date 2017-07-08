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
#include <Wintrust.h>

#include <boost/algorithm/hex.hpp>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"
#include <boost/functional/hash/hash.hpp>

namespace osquery {
namespace tables {

#define CERT_ENCODING (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
  
  const size_t keyUsageSize = 4;
  const std::map<unsigned long, std::string> kKeyUsages = {
    { CERT_DATA_ENCIPHERMENT_KEY_USAGE, "CERT_DATA_ENCIPHERMENT_KEY_USAGE" },
    {CERT_DIGITAL_SIGNATURE_KEY_USAGE, "CERT_DIGITAL_SIGNATURE_KEY_USAGE"},
    {CERT_KEY_AGREEMENT_KEY_USAGE, "CERT_KEY_AGREEMENT_KEY_USAGE"},
    {CERT_KEY_CERT_SIGN_KEY_USAGE, "CERT_KEY_CERT_SIGN_KEY_USAGE"},
    {CERT_KEY_ENCIPHERMENT_KEY_USAGE, "CERT_KEY_ENCIPHERMENT_KEY_USAGE"},
    {CERT_NON_REPUDIATION_KEY_USAGE, "CERT_NON_REPUDIATION_KEY_USAGE"},
    {CERT_OFFLINE_CRL_SIGN_KEY_USAGE, "CERT_OFFLINE_CRL_SIGN_KEY_USAGE"} };

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
  std::set<std::string>* processed;
} ENUM_ARG, *PENUM_ARG;

typedef std::vector<certStoreLocation> storeLocationsContainer;
typedef std::vector<ENUM_ARG> storeContainer;

std::string cryptOIDToString(const char* objId) {
  if(objId == nullptr) {
    return "";
  }
  auto objKeyId = const_cast<char*>(objId);
  auto oidInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, objKeyId, 0);
  return oidInfo == nullptr ? "" : wstringToString(oidInfo->pwszName);
}

// As per the MSDN, key usage occupies 1 or 2 bytes of data. We
// get 4 to cast the value as an INT and OR the usage out of the buff
std::string getKeyUsage(const PCERT_INFO& certInfo) {
  BYTE keyUsageBuff[keyUsageSize];
  auto ret = CertGetIntendedKeyUsage(CERT_ENCODING, certInfo, keyUsageBuff, keyUsageSize);
  // The cert has no intended usage
  if(ret == 0) {
    return "";
  }
  std::vector<std::string> usages;
  auto usage = reinterpret_cast<size_t>(keyUsageBuff);
  for(const auto& kv : kKeyUsages) {
    if(usage & kv.first) {
      usages.push_back(kv.second);
    }
  }
  return join(usages, ",");
}

void getCertCtxProp(const PCCERT_CONTEXT& certContext, unsigned long propId, std::vector<char>& dataBuff) {
  unsigned long dataBuffLen = 0;
  auto ret = CertGetCertificateContextProperty(certContext, propId, nullptr, &dataBuffLen);
  if(ret == 0) {
    VLOG(1) << "Failed to get certificate property struct " << propId << " with: " << GetLastError();
    return;
  }
  dataBuff.resize(dataBuffLen);
  dataBuff.clear();
  ret = CertGetCertificateContextProperty(
    certContext, propId, dataBuff.data(), &dataBuffLen);
  if (ret == 0) {
    VLOG(1) << "Failed to get certificate property struct " << propId << " with: " << GetLastError();
  }
}

std::string getKeyExtendedUsage(PCCERT_CONTEXT certContext) {
  unsigned long certUsageSize;
  PCERT_ENHKEY_USAGE certUsage = nullptr;
  auto ret = CertGetEnhancedKeyUsage(certContext, 0, certUsage, &certUsageSize);
  if(ret == 0) {
    VLOG(1) << "Failed to get size of cert usage structure: " << GetLastError();
    return "";
  }
  certUsage = static_cast<PCERT_ENHKEY_USAGE>(malloc(certUsageSize));
  ret = CertGetEnhancedKeyUsage(certContext, 0, certUsage, &certUsageSize);
  if(ret == 0) {
    free(certUsage);
    VLOG(1) << "Failed to get cert usage: " << GetLastError();
    return "";
  }

  std::vector<std::string> usages;
  for(unsigned int i = 0; i < certUsage->cUsageIdentifier; i++) {
    auto use = cryptOIDToString(certUsage->rgpszUsageIdentifier[i]);
    if(use != "") {
      usages.push_back(use);
    }
  }

  return join(usages, ",");
}

void enumerateCertStore(const HCERTSTORE& certStore, QueryData& results, std::set<std::string>& processedCerts) {
  PCCERT_CONTEXT certContext = nullptr;
  certContext = CertEnumCertificatesInStore(certStore, certContext);
  if (certContext == nullptr) {
    VLOG(1) << "Failed to enumerate certificates certstore with "
            << GetLastError();
    return;
  }

  while (certContext != nullptr) {
    Row r;

    std::vector<char> certHashbuff;
    getCertCtxProp(certContext, CERT_HASH_PROP_ID, certHashbuff);
    std::stringstream hexSha1;
    try {
      boost::algorithm::hex(certHashbuff.data(),
        std::ostream_iterator<char>{hexSha1, ""});
    }
    catch (std::exception /* e */) {
    }
    if(processedCerts.find(hexSha1.str()) != processedCerts.end()) {
      certContext = CertEnumCertificatesInStore(certStore, certContext);
      continue;
    }
    processedCerts.insert(hexSha1.str());
    r["sha1"] = hexSha1.str();
    
    std::vector<char> certName(256, 0x0);
    auto ret = CertGetNameString(certContext,
                                 CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                 0x0,
                                 nullptr,
                                 certName.data(),
                                 static_cast<unsigned long>(certName.size()));
    r["common_name"] = certName.data();

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

    r["self_signed"] = WTHelperCertIsSelfSigned(CERT_ENCODING, certContext->pCertInfo) ? INTEGER(1) : INTEGER(0);

    r["not_valid_before"] =
        std::to_string(filetimeToUnixtime(certContext->pCertInfo->NotBefore));

    r["not_valid_after"] =
        std::to_string(filetimeToUnixtime(certContext->pCertInfo->NotAfter));

    r["signing_algorithm"] = cryptOIDToString(certContext->pCertInfo->SignatureAlgorithm.pszObjId);

    r["key_algorithm"] =
      cryptOIDToString(certContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

    std::vector<std::string> usage;
    std::vector<char> keyUsageBuff;
    
    auto usages = getKeyUsage(certContext->pCertInfo);
    r["key_usage"] = usages;

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
      } catch (std::exception /* e */) { }
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
  auto storeArg = *static_cast<ENUM_ARG*>(arg);

  auto certStoreName = wstringToString(static_cast<LPCWSTR>(systemStore));
  auto certHandle = CertOpenSystemStore(0x0, certStoreName.c_str());
  if (certHandle == nullptr) {
    VLOG(1) << "Failed to open cert store " << certStoreName << " with "
            << GetLastError();
    return FALSE;
  }
  enumerateCertStore(certHandle, *(storeArg.results), *(storeArg.processed));

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
  auto enumArg = static_cast<PENUM_ARG>(arg);

  flags &= CERT_SYSTEM_STORE_MASK;
  flags |= enumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
  auto ret = CertEnumSystemStore(flags,
                                 const_cast<void*>(enumArg->pvStoreLocationPara),
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
  std::set<std::string> processedCerts;

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
