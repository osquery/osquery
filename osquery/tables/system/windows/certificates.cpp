/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <Wintrust.h>
#include <wincrypt.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/tables/system/windows/certificates.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

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

template <typename Iterator>
inline void toHexStr(Iterator begin,
                     Iterator end,
                     std::string& output,
                     bool littleEndian = false) {
  std::string s = std::string(begin, end);
  if (littleEndian) {
    std::reverse_iterator<std::string::iterator> r = s.rbegin();
    boost::algorithm::hex(std::string(r, s.rend()), back_inserter(output));
  } else {
    boost::algorithm::hex(s, back_inserter(output));
  }
}

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
                    std::vector<BYTE>& dataBuff) {
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

/**
 * Given a string with the structure described in `parseSystemStoreString`
 * return the prefix, if it exists.
 */
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

/**
 * Given a string with the structure described in `parseSystemStoreString`
 * return the unlocalized system store name.
 */
LPCWSTR extractStoreName(LPCWSTR sysStoreW) {
  auto* delimiter = wcschr(sysStoreW, L'\\');
  if (delimiter == nullptr) {
    return sysStoreW;
  } else {
    return delimiter + 1;
  }
}

/**
 * Convert a system store name to std::string and localize, if possible.
 */
std::string getLocalizedStoreName(LPCWSTR storeNameW) {
  auto* localizedName = CryptFindLocalizedName(storeNameW);
  if (localizedName == nullptr) {
    return wstringToString(storeNameW);
  } else {
    return wstringToString(localizedName);
  }
}

/**
 * Expects @name to be the `lpServiceStartName` from
 * `QueryServiceConfig`
 */
std::string getServiceSidFromAccountName(const std::string& name) {
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

/**
 * Convert string representation of a SID ("S-1-5-18") into the username.
 * If fails to look up SID, returns an empty string.
 */
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
  LocalFree(sid);
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

/**
 * Given a string that can contain either a service name or SID: if it is
 * a service name, return the SID corresponding to the service account.
 * Otherwise simply return the input string.
 */
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
      /**
       * This would be odd; we couldn't find it in the services table, even
       * though we just saw it in the results from enumerating service
       * certificates?
       */
      VLOG(1) << "Failed to look up service account for " << serviceName;
      return "";
    }

    std::string accountName = results[0]["user_account"];
    sid = getServiceSidFromAccountName(accountName);
    service2sidCache[serviceName] = sid;
  }

  return sid;
}

/**
 * Parse the given system store string whose structure is:
 * `(<prefix>\)?<unlocalized system store name>`
 * (e.g. "My")
 * (e.g. "S-1-5-18\My")
 * (e.g. "SshdBroker\My")
 *
 * <prefix> can be a SID, service name (`SshdBroker`) (for service stores), or
 * SID with `_Classes` appended (for user accounts). If it exists, it is
 * followed by a backslash.
 * <unlocalized system store name> would be something like `My`, `CA`, etc.
 *
 * @param sysStoreW System store string
 * @param storeLocation System store location containing this system store
 * @param service2sidCache Cache of service name to SID. A new cache is created
 * for every query to keep it from getting stale.
 * @param serviceNameOrUserId The prefix, if it exists. (output)
 * @param sid SID corresponding to this certificate store (or empty) (output)
 * @param storeName The (localized, if possible) name of the certificate store,
 * with no prefix of any kind. (output)
 */
void parseSystemStoreString(LPCWSTR sysStoreW,
                            const std::string& storeLocation,
                            ServiceNameMap& service2sidCache,
                            std::string& serviceNameOrUserId,
                            std::string& sid,
                            std::string& storeName) {
  LPCWSTR storeNameUnlocalizedW = extractStoreName(sysStoreW);
  storeName = getLocalizedStoreName(storeNameUnlocalizedW);
  serviceNameOrUserId = extractServiceOrUserId(sysStoreW);

  /**
   * Except for the conditions detailed below, `sid` is either empty, or a
   * SID after this assignment
   */
  sid = serviceNameOrUserId;

  if (storeLocation == "Services") {
    /**
     * If we are enumerating the "Services" store, we need to look up the
     * SID for the service
     */
    sid = getServiceSid(serviceNameOrUserId, service2sidCache);
  } else if (storeLocation == "Users") {
    /**
     * If we are enumerating the "Users" store, we need to either convert
     * the `.DEFAULT` user ID (alias for Local System), or trim a `_Classes`
     * suffix that sometimes appears.
     */

    if (serviceNameOrUserId == ".DEFAULT") {
      sid = kLocalSystem;
    }

    /**
     * There are cert store user IDs that are structured <SID>_Classes.
     * The corresponding SID is simply this string with the suffix removed.
     */
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
  unsigned long propid;
  unsigned long unknown;
  unsigned long size;
};
#pragma pack(pop)

/**
 * This function extracts an encoded certificate from a proprietary Windows
 * file format, which is described in the links below. Briefly, the file is
 * an array of elements where each element contains a header followed by a
 * variable length data buffer. The encoded certificate is stored in the data
 * buffer of one of these elements whose header has a specific `propid` field.
 *
 * Links:
 * https://itsme.home.xs4all.nl/projects/xda/smartphone-certificates.html
 * https://github.com/wine-mirror/wine/blob/f9301c2b66450a1cdd986e9052fcaa76535ba8b7/dlls/crypt32/crypt32_private.h#L146
 */
Status getEncodedCert(std::basic_istream<BYTE>& blob,
                      std::vector<BYTE>& encodedCert) {
  static const unsigned long CERT_CERT_PROP_ID = 0x20;

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
                const std::string& storeId,
                const std::string& sid,
                const std::string& storeName,
                const std::string& username,
                const std::string& storeLocation,
                QueryData& results) {
  std::vector<BYTE> fingerprintBuff;
  getCertCtxProp(certContext, CERT_HASH_PROP_ID, fingerprintBuff);
  std::string fingerprint;
  toHexStr(fingerprintBuff.begin(), fingerprintBuff.end(), fingerprint);

  Row r;
  r["sid"] = sid;
  r["username"] = username;
  r["store_id"] = storeId;
  r["sha1"] = fingerprint;
  std::vector<WCHAR> certBuff;
  certBuff.resize(256, 0);
  std::fill(certBuff.begin(), certBuff.end(), 0);
  CertGetNameString(certContext,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    nullptr,
                    certBuff.data(),
                    static_cast<unsigned long>(certBuff.size()));
  r["common_name"] = wstringToString(certBuff.data());

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
  r["subject"] = subjSize == 0 ? "" : wstringToString(certBuff.data());

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
  r["issuer"] = issuerSize == 0 ? "" : wstringToString(certBuff.data());

  // TODO(#5654) 1: Find the right API calls to get whether a cert is for a CA
  r["ca"] = INTEGER(-1);

  r["self_signed"] =
      WTHelperCertIsSelfSigned(CERT_ENCODING, certContext->pCertInfo)
          ? INTEGER(1)
          : INTEGER(0);

  r["not_valid_before"] =
      BIGINT(filetimeToUnixtime(certContext->pCertInfo->NotBefore));

  r["not_valid_after"] =
      BIGINT(filetimeToUnixtime(certContext->pCertInfo->NotAfter));

  r["signing_algorithm"] =
      cryptOIDToString(certContext->pCertInfo->SignatureAlgorithm.pszObjId);

  r["key_algorithm"] = cryptOIDToString(
      certContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

  r["key_usage"] = getKeyUsage(certContext->pCertInfo);

  r["key_strength"] = INTEGER(
      (certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData) * 8);

  std::vector<BYTE> keypropBuff;
  getCertCtxProp(certContext, CERT_KEY_IDENTIFIER_PROP_ID, keypropBuff);
  std::string subjectKeyId;
  toHexStr(keypropBuff.begin(), keypropBuff.end(), subjectKeyId);
  r["subject_key_id"] = subjectKeyId;

  r["path"] =
      storeLocation + "\\" + constructDisplayStoreName(storeId, storeName);
  r["store_location"] = storeLocation;
  r["store"] = storeName;

  std::string serial;
  toHexStr(certContext->pCertInfo->SerialNumber.pbData,
           certContext->pCertInfo->SerialNumber.pbData +
               certContext->pCertInfo->SerialNumber.cbData,
           serial,
           true);
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

        toHexStr(authKeyIdBlob->KeyId.pbData,
                 authKeyIdBlob->KeyId.pbData + authKeyIdBlob->KeyId.cbData,
                 authKeyId);
      } else {
        VLOG(1) << "Failed to decode authority_key_id with (" << GetLastError()
                << ")";
      }
    }
  }
  r["authority_key_id"] = authKeyId;

  results.push_back(r);
}

Status expandEnvironmentVariables(const std::string& src, std::string& dest) {
  auto srcWstring = stringToWstring(src);
  auto srcW = srcWstring.c_str();
  auto expandedSize = ExpandEnvironmentStringsW(srcW, nullptr, 0);
  if (expandedSize == 0) {
    return Status::failure("Unable to get expanded size");
  }

  std::vector<wchar_t> buf(expandedSize);
  auto ret = ExpandEnvironmentStringsW(srcW, buf.data(), expandedSize);
  if (ret == 0) {
    return Status::failure("Environment variable expansion failed");
  } else if (ret != expandedSize) {
    return Status::failure("Partial data written");
  }

  dest = wstringToString(buf.data());
  return Status::success();
}

void findUserPersonalCertsOnDisk(const std::string& username,
                                 const std::string& storeId,
                                 const std::string& sid,
                                 const std::string& storeName,
                                 const std::string& storeLocation,
                                 QueryData& results) {
  VLOG(1) << "Checking disk for Personal certificates for user: " << username;

  std::string homeDir;
  auto homeDirUnexpanded = getUserHomeDir(sid);
  if (homeDirUnexpanded.empty()) {
    VLOG(1) << "Could not find home dir for account " << username;
    return;
  }

  // System accounts have environment variables in their paths
  auto ret = expandEnvironmentVariables(homeDirUnexpanded, homeDir);
  if (!ret.ok() || homeDir.empty()) {
    VLOG(1) << "Error getting home directory for account " << username;
    return;
  }

  std::stringstream certsPath;
  certsPath
      << homeDir
      << "\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates";

  try {
    for (auto& file : fs::directory_iterator(fs::path(certsPath.str()))) {
      std::basic_ifstream<BYTE> inp(file.path().string(), std::ios::binary);

      std::vector<BYTE> encodedCert;
      auto ret = getEncodedCert(inp, encodedCert);
      if (!ret.ok()) {
        continue;
      }

      auto ctx = CertCreateCertificateContext(
          X509_ASN_ENCODING,
          encodedCert.data(),
          static_cast<unsigned long>(encodedCert.size()));

      addCertRow(
          ctx, storeId, sid, storeName, username, storeLocation, results);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << certsPath.str() << ": " << e.what();
  }
}

/**
 * Enumerate and process a certificate store
 */
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
    // Personal stores for other users come back as empty, even if they are not.
    auto is_personal_store = storeName == "Personal" && !username.empty();
    // Avoid duplicate rows for personal certs we've already inserted up front
    auto not_already_added =
        storeLocation != "Users" || boost::ends_with(storeId, "_Classes");

    if (is_personal_store && not_already_added) {
      // TODO(#5654) 2: Potential future optimization
      findUserPersonalCertsOnDisk(
          username, storeId, sid, storeName, storeLocation, results);
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
        certContext, storeId, sid, storeName, username, storeLocation, results);

    certContext = CertEnumCertificatesInStore(certStore, certContext);
  }
}

/**
 * Windows API callback for processing a system cert store
 *
 * This function returns TRUE, even when error handling, because returning
 * FALSE stops enumeration.
 *
 * @systemStore: Could include a SID at the start ("SID-1234-blah-1001\MY")
 * instead of only being the system store name ("MY")
 */
BOOL WINAPI certEnumSystemStoreCallback(const void* systemStore,
                                        unsigned long flags,
                                        PCERT_SYSTEM_STORE_INFO storeInfo,
                                        void* reserved,
                                        void* arg) {
  auto* storeArg = static_cast<ENUM_ARG*>(arg);
  auto* sysStoreW = static_cast<LPCWSTR>(systemStore);

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

/**
 * Windows API callback for processing a system cert store location
 */
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

/**
 * A user's `Personal` certs are stored on disk and not in the registry.
 * Furthermore, when using the enumeration APIs, other users' Personal certs
 * are not visible. This function proactively retrieves these certs from
 * disk so that the table is guaranteed to, at the very least, list any
 * existing Personal certs for all local users, regardless of whether those
 * users' registry hives are currently mounted.
 */
void genPersonalCertsFromDisk(QueryData& results) {
  SQL sql("SELECT uuid, username FROM users");
  if (!sql.ok()) {
    VLOG(1) << sql.getStatus().getMessage();
    return;
  }

  for (const auto& row : sql.rows()) {
    auto sid = row.at("uuid");
    auto username = row.at("username");

    findUserPersonalCertsOnDisk(
        username, sid, sid, "Personal", "Users", results);
  }
}

/**
 * Use the standard enumeration APIs to retrieve certificates.
 */
void genNonPersonalCerts(QueryData& results) {
  ENUM_ARG enumArg;

  unsigned long flags = 0;
  unsigned long locationId = CERT_SYSTEM_STORE_CURRENT_USER_ID;

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
