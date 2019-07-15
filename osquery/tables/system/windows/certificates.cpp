/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>

#include <Wintrust.h>
#include <wincrypt.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/filesystem.hpp>

#include <osquery/logger.h>
#include <osquery/process/windows/process_ops.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/tables/system/windows/certificates.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

using ServiceNameMap = std::unordered_map<std::string, std::string>;

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
  std::string storeLocation;
  ServiceNameMap service2sidCache;
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

std::string constructDisplayStoreName(const std::string& serviceNameOrUserId,
                                      const std::string& storeNameLocalized) {
  if (serviceNameOrUserId.empty()) {
    return storeNameLocalized;
  } else {
    return serviceNameOrUserId + "\\" + storeNameLocalized;
  }
}

/// Given a string with the structure described in `parseSystemStoreString`
/// return the prefix, if it exists.
std::string extractServiceOrUserId(LPCWSTR sysStoreW) {
  const auto& certStoreNameString = wstringToString(sysStoreW);

  // Check if there was a backslash, and parse id from start if so
  auto delimiter = certStoreNameString.find('\\');
  if (delimiter == std::string::npos) {
    return "";
  } else {
    return certStoreNameString.substr(0, delimiter);
  }
}

/// Given a string with the structure described in `parseSystemStoreString`
/// return the unlocalized system store name.
LPCWSTR extractStoreName(LPCWSTR sysStoreW) {
  auto* delimiter = wcschr(sysStoreW, L'\\');
  if (delimiter == nullptr) {
    return sysStoreW;
  } else {
    return delimiter + 1;
  }
}

/// Convert a system store name to std::string and localize, if possible.
std::string getLocalizedStoreName(LPCWSTR storeNameW) {
  auto* localizedName = CryptFindLocalizedName(storeNameW);
  if (localizedName == nullptr) {
    return wstringToString(storeNameW);
  } else {
    return wstringToString(localizedName);
  }
}

/// Expects @name to be the `lpServiceStartName` from
/// `QueryServiceConfig`
std::string getSidFromAccountName(const std::string& name) {
  // `lpServiceStartName` has been observed to contain both uppercase
  // and lowercase versions of these values
  if (boost::iequals(name, "LocalSystem")) {
    return kLocalSystem;
  } else if (boost::iequals(name, "NT Authority\\LocalService")) {
    return kLocalService;
  } else if (boost::iequals(name, "NT Authority\\NetworkService")) {
    return kNetworkService;
  }
  return "";
}

/// Convert string representation of a SID ("S-1-5-18") into the username.
/// If fails to look up SID, returns an empty string.
std::string getUsernameFromSid(const std::string& sidString) {
  if (sidString.empty()) {
    return "";
  }

  PSID sid;
  auto ret = ConvertStringSidToSidA(sidString.c_str(), &sid);
  if (ret == 0) {
    VLOG(1) << "Convert SID to string failed with " << GetLastError()
            << " for sid: " << sidString;
    return "";
  }

  auto eUse = SidTypeUnknown;
  unsigned long unameSize = 0;
  unsigned long domNameSize = 1;
  // LookupAccountSid first gets the size of the username buff required.
  LookupAccountSidW(
      nullptr, sid, nullptr, &unameSize, nullptr, &domNameSize, &eUse);

  std::vector<wchar_t> uname(unameSize);
  std::vector<wchar_t> domName(domNameSize);
  ret = LookupAccountSidW(nullptr,
                          sid,
                          uname.data(),
                          &unameSize,
                          domName.data(),
                          &domNameSize,
                          &eUse);

  if (ret == 0) {
    VLOG(1) << "LookupAccountSid failed with " << GetLastError()
            << " for sid: " << sidString;
    return "";
  }

  return wstringToString(uname.data());
}

bool isValidSid(const std::string& maybeSid) {
  return getUsernameFromSid(maybeSid).length() != 0;
}

/// Given a string that can contain either a service name or SID: if it is
/// a service name, return the SID corresponding to the service account.
/// Otherwise simply return the input string.
std::string getServiceSid(const std::string& serviceNameOrSid,
                          ServiceNameMap& service2sidCache) {
  if (isValidSid(serviceNameOrSid)) {
    return serviceNameOrSid;
  }

  const std::string& serviceName = serviceNameOrSid;
  std::string sid;

  if (service2sidCache.count(serviceName)) {
    sid = service2sidCache[serviceName];
  } else {
    auto results = SQL::selectAllFrom("services", "name", EQUALS, serviceName);

    if (results.empty()) {
      // This would be odd; we couldn't find it in the services table, even
      // though we just saw it in the results from enumerating service
      // certificates?
      VLOG(1) << "Failed to look up service account for " << serviceName;
      return "";
    }

    std::string accountName = results[0]["user_account"];
    sid = getSidFromAccountName(accountName);
    service2sidCache[serviceName] = sid;
  }

  return sid;
}

/// Parse the given system store string whose structure is:
/// `(<prefix>\)?<unlocalized system store name>`
/// (e.g. "My")
/// (e.g. "S-1-5-18\My")
/// (e.g. "SshdBroker\My")
///
/// <prefix> can be a SID, service name (`SshdBroker`) (for service stores), or
/// SID with `_Classes` appended (for user accounts). If it exists, it is
/// followed by a backslash.
/// <unlocalized system store name> would be something like `My`, `CA`, etc.
///
/// The inputs are:
/// @sysStoreW: System store string
/// @storeLocation: System store location containing this system store
/// @service2sidCache: Cache of service name to SID. A new cache is created for
/// every query to keep it from getting stale.
///
/// The outputs are:
/// @serviceNameOrUserId: The prefix, if it exists.
/// @sid: SID corresponding to this certificate store (or empty)
/// @storeName: The (localized, if possible) name of the certificate store,
///             with no prefix of any kind.
void parseSystemStoreString(LPCWSTR sysStoreW,
                            const std::string& storeLocation,
                            ServiceNameMap& service2sidCache,
                            std::string& serviceNameOrUserId,
                            std::string& sid,
                            std::string& storeName) {
  LPCWSTR storeNameUnlocalizedW = extractStoreName(sysStoreW);
  storeName = getLocalizedStoreName(storeNameUnlocalizedW);
  serviceNameOrUserId = extractServiceOrUserId(sysStoreW);

  // Except for the conditions detailed below, `sid` is either empty, or a
  // SID after this assignment
  sid = serviceNameOrUserId;

  if (storeLocation == "Services") {
    // If we are enumerating the "Services" store, we need to look up the
    // SID for the service
    sid = getServiceSid(serviceNameOrUserId, service2sidCache);
  } else if (storeLocation == "Users") {
    // If we are enumerating the "Users" store, we need to either convert
    // the `.DEFAULT` user ID (alias for Local System), or trim a `_Classes`
    // suffix that sometimes appears.

    if (serviceNameOrUserId == ".DEFAULT") {
      sid = kLocalSystem;
    }

    // There are cert store user IDs that are structured <SID>_Classes.
    // The corresponding SID is simply this string with the suffix removed.
    const static std::string suffix("_Classes");
    if (boost::ends_with(serviceNameOrUserId, suffix)) {
      sid = serviceNameOrUserId.substr(
          0, serviceNameOrUserId.length() - suffix.length());
    }
  } else if (storeLocation == "CurrentUser") {
    auto currentUserInfoSmartPtr = getCurrentUserInfo();
    if (currentUserInfoSmartPtr == nullptr) {
      VLOG(1) << "Accessing current user info failed (" << GetLastError()
              << ")";
    } else {
      auto ptu = reinterpret_cast<PTOKEN_USER>(currentUserInfoSmartPtr.get());
      sid = psidToString(ptu->User.Sid);
    }
  }
}

#pragma pack(push, 1)
struct Header {
  DWORD propid;
  DWORD unknown;
  DWORD size;
};
#pragma pack(pop)

Status getEncodedCert(std::basic_istream<BYTE>& blob,
                      std::vector<BYTE>& encodedCert) {
  // See these links for details on this magic number:
  // https://itsme.home.xs4all.nl/projects/xda/smartphone-certificates.html
  // https://github.com/wine-mirror/wine/blob/f9301c2b66450a1cdd986e9052fcaa76535ba8b7/dlls/crypt32/crypt32_private.h#L146
  static const DWORD CERT_CERT_PROP_ID = 0x20;

  Header hdr;

  while (true) {
    blob.read(reinterpret_cast<BYTE*>(&hdr), sizeof(hdr));
    if (!blob.good()) {
      return Status::failure("Malformed certificate blob");
    }

    if (hdr.propid != CERT_CERT_PROP_ID) {
      blob.ignore(hdr.size);
      if (!blob.good()) {
        return Status::failure("Malformed certificate blob");
      }
      continue;
    }

    encodedCert.resize(hdr.size);
    blob.read(encodedCert.data(), hdr.size);
    if (!blob.good()) {
      return Status::failure("EOF in certificate blob when reading data");
    }
    break;
  }

  return Status::success();
}

void addCertRow(PCCERT_CONTEXT certContext,
                QueryData& results,
                std::string storeId,
                std::string sid,
                std::string storeName,
                std::string username,
                std::string storeLocation) {
  // Get the cert fingerprint and ensure we haven't already processed it
  std::vector<char> certBuff;
  getCertCtxProp(certContext, CERT_HASH_PROP_ID, certBuff);
  std::string fingerprint;
  boost::algorithm::hex(std::string(certBuff.begin(), certBuff.end()),
                        back_inserter(fingerprint));

  Row r;
  r["sid"] = sid;
  r["username"] = username;
  r["store_id"] = storeId;
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
  TLOG << "    cert name: " << certBuff.data();

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

  r["key_strength"] = INTEGER(
      (certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData) * 8);

  certBuff.clear();
  getCertCtxProp(certContext, CERT_KEY_IDENTIFIER_PROP_ID, certBuff);
  std::string subjectKeyId;
  boost::algorithm::hex(std::string(certBuff.begin(), certBuff.end()),
                        back_inserter(subjectKeyId));
  r["subject_key_id"] = subjectKeyId;

  r["path"] =
      storeLocation + "\\" + constructDisplayStoreName(storeId, storeName);
  r["store_location"] = storeLocation;
  r["store"] = storeName;

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
        VLOG(1) << "Failed to decode authority_key_id with (" << GetLastError()
                << ")";
      }
    }
  }
  r["authority_key_id"] = authKeyId;

  results.push_back(r);
}

void findUserPersonalCertsOnDisk(const std::string& username,
                                 QueryData& results,
                                 std::string storeId,
                                 std::string sid,
                                 std::string storeName,
                                 std::string storeLocation) {
  std::stringstream certsPath;
  certsPath
      << "C:\\Users\\" << username
      << "\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates";

  try {
    for (fs::directory_entry& x :
         fs::directory_iterator(fs::path(certsPath.str()))) {
      std::basic_ifstream<BYTE> inp(x.path().string(), std::ios::binary);

      std::vector<BYTE> encodedCert;
      auto ret = getEncodedCert(inp, encodedCert);
      if (!ret.ok()) {
        return;
      }

      auto ctx =
          CertCreateCertificateContext(X509_ASN_ENCODING,
                                       encodedCert.data(),
                                       static_cast<DWORD>(encodedCert.size()));

      addCertRow(
          ctx, results, storeId, sid, storeName, username, storeLocation);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << certsPath.str() << ": " << e.what();
  }
}

/// Enumerate and process a certificate store
void enumerateCertStore(const HCERTSTORE& certStore,
                        LPCWSTR sysStoreW,
                        const std::string& storeLocation,
                        ServiceNameMap& service2sidCache,
                        QueryData& results) {
  std::string storeId, sid, storeName;
  parseSystemStoreString(
      sysStoreW, storeLocation, service2sidCache, storeId, sid, storeName);

  std::string username = getUsernameFromSid(sid);

  auto certContext = CertEnumCertificatesInStore(certStore, nullptr);

  if (certContext == nullptr && GetLastError() == CRYPT_E_NOT_FOUND) {
    TLOG << "    Store was empty.";

    // Personal stores for other users come back as empty, even if they are not.
    if (storeName == "Personal" && !username.empty()) {
      // Avoid duplicate rows for personal certs we've already inserted up
      // front.
      if (storeLocation != "Users" || boost::ends_with(storeId, "_Classes")) {
        TLOG << "    Trying harder to get Personal store.";

        // TODO: This can technically be optimized. In certain cases, we will
        // end up retrieving Personal certificates from disk that have already
        // been fetched for a user/SID. For example, the Services store
        // location has stores like
        // S-1-5-21-2821152761-3909955410-1545212275-1001\My. That user's
        // Personal certs will have already been fetched up front and in this
        // specific case, we will refetch from disk. We could conceivably save
        // those results, and reuse them here. Only thing is we'd need to update
        // the storeId and storeLocation fields to match where we currently are
        // in the enumeration process.
        findPersonalCertsOnDisk(
            username, results, storeId, sid, storeName, storeLocation);
      }
    }
    return;
  }

  if (certContext == nullptr && GetLastError() != CRYPT_E_NOT_FOUND) {
    VLOG(1) << "Certificate store access failed:  " << storeLocation << "\\"
            << constructDisplayStoreName(storeId, storeName) << " with "
            << GetLastError();
    return;
  }

  while (certContext != nullptr) {
    addCertRow(
        certContext, results, storeId, sid, storeName, username, storeLocation);

    certContext = CertEnumCertificatesInStore(certStore, certContext);
  }
}

/// Windows API callback for processing a system cert store
///
/// This function returns TRUE, even when error handling, because returning
/// FALSE stops enumeration.
///
/// @systemStore: Could include a SID at the start ("SID-1234-blah-1001\MY")
/// instead of only being the system store name ("MY")
BOOL WINAPI certEnumSystemStoreCallback(const void* systemStore,
                                        unsigned long flags,
                                        PCERT_SYSTEM_STORE_INFO storeInfo,
                                        void* reserved,
                                        void* arg) {
  auto* storeArg = static_cast<ENUM_ARG*>(arg);
  auto* sysStoreW = static_cast<LPCWSTR>(systemStore);

  VLOG(1) << "  Enumerating cert store: " << wstringToString(sysStoreW);

  auto systemStoreLocation = flags & CERT_SYSTEM_STORE_LOCATION_MASK;

  auto certHandle = CertOpenStore(
      CERT_STORE_PROV_SYSTEM, 0, NULL, systemStoreLocation, sysStoreW);

  if (certHandle == nullptr) {
    VLOG(1) << "Failed to open cert store " << wstringToString(sysStoreW)
            << " with " << GetLastError();
    return TRUE;
  }

  enumerateCertStore(certHandle,
                     sysStoreW,
                     storeArg->storeLocation,
                     storeArg->service2sidCache,
                     *storeArg->results);

  auto ret = CertCloseStore(certHandle, 0);
  if (ret != TRUE) {
    VLOG(1) << "Closing cert store failed with " << GetLastError();
    return TRUE;
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

  VLOG(1) << "Enumerating cert store location: " << enumArg->storeLocation;

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

/// A user's `Personal` certs are stored on disk and not in the registry.
/// Furthermore, when using the enumeration APIs, other users' Personal certs
/// are not visible. This function proactively retrieves these certs from
/// disk so that the table is guaranteed to, at the very least, list any
/// existing Personal certs for all local users, regardless of whether those
/// users' registry hives are currently mounted.
void genPersonalCertsFromDisk(QueryData& results) {
  auto users = SQL::selectAllFrom("users");
  for (const auto& row : users) {
    auto sid = row.at("uuid");
    auto username = row.at("username");

    findUserPersonalCertsOnDisk(username,
                                results,
                                sid,
                                sid,
                                "Personal", // storeName
                                "Users" // storeLocation
    );
  }
}

/// Use the standard enumeration APIs to retrieve certificates.
void genNonPersonalCerts(QueryData& results) {
  ENUM_ARG enumArg;

  unsigned long flags = 0;
  DWORD locationId = CERT_SYSTEM_STORE_CURRENT_USER_ID;

  enumArg.dwFlags = flags;
  enumArg.pvStoreLocationPara = nullptr;
  enumArg.results = &results;

  flags &= ~CERT_SYSTEM_STORE_LOCATION_MASK;
  flags |= (locationId << CERT_SYSTEM_STORE_LOCATION_SHIFT) &
           CERT_SYSTEM_STORE_LOCATION_MASK;

  auto ret = CertEnumSystemStoreLocation(
      flags, &enumArg, certEnumSystemStoreLocationsCallback);

  if (ret != 1) {
    VLOG(1) << "Failed to enumerate system store locations with "
            << GetLastError();
  }
}

QueryData genCerts(QueryContext& context) {
  QueryData results;

  genPersonalCertsFromDisk(results);
  genNonPersonalCerts(results);

  return results;
}

} // namespace tables
} // namespace osquery
