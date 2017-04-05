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
/// clang-format off
#include <LM.h>
#include <sddl.h>
// clang-format on

#include <iterator>
#include <map>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::set<int> kRegistryStringTypes = {
    REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ};

const std::map<std::string, HKEY> kRegistryHives = {
    {"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT},
    {"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG},
    {"HKEY_CURRENT_USER", HKEY_CURRENT_USER},
    {"HKEY_CURRENT_USER_LOCAL_SETTINGS", HKEY_CURRENT_USER_LOCAL_SETTINGS},
    {"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE},
    {"HKEY_PERFORMANCE_DATA", HKEY_PERFORMANCE_DATA},
    {"HKEY_PERFORMANCE_NLSTEXT", HKEY_PERFORMANCE_NLSTEXT},
    {"HKEY_PERFORMANCE_TEXT", HKEY_PERFORMANCE_TEXT},
    {"HKEY_USERS", HKEY_USERS},
};

const std::map<DWORD, std::string> kRegistryTypes = {
    {REG_BINARY, "REG_BINARY"},
    {REG_DWORD, "REG_DWORD"},
    {REG_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN"},
    {REG_EXPAND_SZ, "REG_EXPAND_SZ"},
    {REG_LINK, "REG_LINK"},
    {REG_MULTI_SZ, "REG_MULTI_SZ"},
    {REG_NONE, "REG_NONE"},
    {REG_QWORD, "REG_QWORD"},
    {REG_SZ, "REG_SZ"},
    {REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR"},
    {REG_RESOURCE_LIST, "REG_RESOURCE_LIST"},
};

Status getUsernameFromKey(const std::string& key, std::string& rUsername) {
  Status status;

  if (boost::starts_with(key, "HKEY_USERS")) {
    PSID sid;
    if (!ConvertStringSidToSidA(osquery::split(key, kRegSep)[1].c_str(),
                                &sid)) {
      status = Status(GetLastError(), "Could not convert string to sid");
    } else {
      wchar_t accntName[UNLEN] = {0};
      wchar_t domName[DNLEN] = {0};
      unsigned long accntNameLen = UNLEN;
      unsigned long domNameLen = DNLEN;
      SID_NAME_USE eUse;
      if (!LookupAccountSidW(nullptr,
                             sid,
                             accntName,
                             &accntNameLen,
                             domName,
                             &domNameLen,
                             &eUse)) {
        status = Status(GetLastError(), "Could not find sid");
      } else {
        rUsername = std::move(wstringToString(accntName));
      }
    }
  } else {
    status = Status(1, "Can not extrat username from non-HKEY_USERS key");
  }
  return status;
}

inline void explodeRegistryPath(const std::string& path,
                                std::string& rHive,
                                std::string& rKey) {
  auto toks = osquery::split(path, kRegSep);
  rHive = toks.front();
  toks.erase(toks.begin());
  rKey = osquery::join(toks, kRegSep);
}

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& keyPath, QueryData& results) {
  std::string hive;
  std::string key;
  explodeRegistryPath(keyPath, hive, key);

  if (kRegistryHives.count(hive) != 1) {
    return;
  }

  HKEY hRegistryHandle;
  auto ret = RegOpenKeyEx(kRegistryHives.at(hive),
                          TEXT(key.c_str()),
                          0,
                          KEY_READ,
                          &hRegistryHandle);

  if (ret != ERROR_SUCCESS) {
    return;
  }

  const DWORD maxKeyLength = 255;
  const DWORD maxValueName = 16383;
  TCHAR achClass[MAX_PATH] = TEXT("");
  DWORD cchClassName = MAX_PATH;
  DWORD cSubKeys = 0;
  DWORD cbMaxSubKey;
  DWORD cchMaxClass;
  DWORD cValues;
  DWORD cchMaxValueName;
  DWORD cbMaxValueData;
  DWORD cbSecurityDescriptor;
  DWORD retCode;
  FILETIME ftLastWriteTime;
  retCode = RegQueryInfoKey(hRegistryHandle,
                            achClass,
                            &cchClassName,
                            nullptr,
                            &cSubKeys,
                            &cbMaxSubKey,
                            &cchMaxClass,
                            &cValues,
                            &cchMaxValueName,
                            &cbMaxValueData,
                            &cbSecurityDescriptor,
                            &ftLastWriteTime);

  TCHAR achKey[maxKeyLength];
  DWORD cbName;

  // Process registry subkeys
  if (cSubKeys > 0) {
    for (DWORD i = 0; i < cSubKeys; i++) {
      cbName = maxKeyLength;
      retCode = RegEnumKeyEx(hRegistryHandle,
                             i,
                             achKey,
                             &cbName,
                             nullptr,
                             nullptr,
                             nullptr,
                             &ftLastWriteTime);
      if (retCode != ERROR_SUCCESS) {
        continue;
      }
      Row r;
      r["key"] = keyPath;
      r["type"] = "subkey";
      r["name"] = achKey;
      r["path"] = keyPath + kRegSep + achKey;
      r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));
      results.push_back(r);
    }
  }

  if (cValues <= 0) {
    return;
  }

  DWORD cchValue = maxKeyLength;
  TCHAR achValue[maxValueName];
  BYTE* bpDataBuff =
      (cbMaxValueData == 0) ? nullptr : new BYTE[cbMaxValueData]();

  // Process registry values
  for (size_t i = 0, retCode = ERROR_SUCCESS; i < cValues; i++) {
    size_t cnt = 0;
    cchValue = maxValueName;
    achValue[0] = '\0';

    retCode = RegEnumValue(hRegistryHandle,
                           static_cast<DWORD>(i),
                           achValue,
                           &cchValue,
                           nullptr,
                           nullptr,
                           nullptr,
                           nullptr);
    if (retCode != ERROR_SUCCESS) {
      continue;
    }

    DWORD lpData = cbMaxValueData;
    DWORD lpType;

    retCode = RegQueryValueEx(
        hRegistryHandle, achValue, 0, &lpType, bpDataBuff, &lpData);
    if (retCode != ERROR_SUCCESS) {
      continue;
    }

    // It's possible for registry entries to have been inserted incorrectly
    // resulting in non-null-terminated strings
    if (bpDataBuff != nullptr && lpData != 0 &&
        kRegistryStringTypes.find(lpType) != kRegistryStringTypes.end()) {
      bpDataBuff[lpData - 1] = 0x00;
    }

    Row r;
    r["key"] = keyPath;
    r["name"] = ((achValue[0] == '\0') ? "(Default)" : achValue);
    r["path"] = keyPath + kRegSep + achValue;
    if (kRegistryTypes.count(lpType) > 0) {
      r["type"] = kRegistryTypes.at(lpType);
    } else {
      r["type"] = "UNKNOWN";
    }
    r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));

    if (bpDataBuff != nullptr) {
      /// REG_LINK is a Unicode string, which in Windows is wchar_t
      char* regLinkStr = nullptr;
      if (lpType == REG_LINK) {
        regLinkStr = new char[cbMaxValueData];
        const size_t newSize = cbMaxValueData;
        size_t convertedChars = 0;
        wcstombs_s(&convertedChars,
                   regLinkStr,
                   newSize,
                   (wchar_t*)bpDataBuff,
                   _TRUNCATE);
      }

      BYTE* bpDataBuffTmp = bpDataBuff;
      std::vector<std::string> multiSzStrs;
      std::vector<char> regBinary;
      std::string data;

      switch (lpType) {
      case REG_FULL_RESOURCE_DESCRIPTOR:
      case REG_RESOURCE_LIST:
      case REG_BINARY:
        for (size_t i = 0; i < cbMaxValueData; i++) {
          regBinary.push_back((char)bpDataBuff[i]);
        }
        boost::algorithm::hex(
            regBinary.begin(), regBinary.end(), std::back_inserter(data));
        r["data"] = data;
        break;
      case REG_DWORD:
        r["data"] = std::to_string(*((int*)bpDataBuff));
        break;
      case REG_DWORD_BIG_ENDIAN:
        r["data"] = std::to_string(_byteswap_ulong(*((int*)bpDataBuff)));
        break;
      case REG_EXPAND_SZ:
        r["data"] = std::string((char*)bpDataBuff);
        break;
      case REG_LINK:
        r["data"] = std::string(regLinkStr);
        break;
      case REG_MULTI_SZ:
        while (*bpDataBuffTmp != 0x00) {
          std::string s((char*)bpDataBuffTmp);
          bpDataBuffTmp += s.size() + 1;
          multiSzStrs.push_back(s);
        }
        r["data"] = boost::algorithm::join(multiSzStrs, ",");
        break;
      case REG_NONE:
        r["data"] = "(zero-length binary value)";
        break;
      case REG_QWORD:
        r["data"] = std::to_string(*((unsigned long long*)bpDataBuff));
        break;
      case REG_SZ:
        r["data"] = std::string((char*)bpDataBuff);
        break;
      default:
        r["data"] = "";
        break;
      }
      if (regLinkStr != nullptr) {
        delete[](regLinkStr);
      }
      ZeroMemory(bpDataBuff, cbMaxValueData);
    }
    results.push_back(r);
  }
  if (bpDataBuff != nullptr) {
    delete[](bpDataBuff);
  }
  RegCloseKey(hRegistryHandle);
}

static inline void populateDefaultKeys(std::set<std::string>& rKeys) {
  boost::copy(kRegistryHives | boost::adaptors::map_keys,
              std::inserter(rKeys, rKeys.end()));
}

static inline void populateSubkeys(std::set<std::string>& rKeys,
                                   bool replaceKeys = false) {
  std::set<std::string> newKeys;
  if (!replaceKeys) {
    newKeys = rKeys;
  }

  for (const auto& key : rKeys) {
    QueryData regResults;
    queryKey(key, regResults);
    for (const auto& r : regResults) {
      if (r.at("type") == "subkey") {
        newKeys.insert(r.at("path"));
      }
    }
  }
  rKeys = std::move(newKeys);
}

static inline void appendSubkeyToKeys(const std::string& subkey,
                                      std::set<std::string>& rKeys) {
  std::set<std::string> newKeys{};
  for (auto& key : rKeys) {
    newKeys.insert(std::move(key) + kRegSep + subkey);
  }
  rKeys = std::move(newKeys);
}

static inline Status populateAllKeysRecursive(
    std::set<std::string>& rKeys,
    size_t currDepth = 1,
    size_t maxDepth = kRegMaxRecursiveDepth) {
  if (currDepth > maxDepth) {
    return Status(1, "Max recursive depth reached");
  }

  auto size_pre = rKeys.size();
  populateSubkeys(rKeys);
  if (size_pre < rKeys.size()) {
    auto status = populateAllKeysRecursive(rKeys, ++currDepth);
    if (!status.ok()) {
      return status;
    }
  }

  return Status(0, "OK");
}

Status expandRegistryGlobs(const std::string& pattern,
                           std::set<std::string>& results) {
  auto pathElems = osquery::split(pattern, kRegSep);
  if (pathElems.size() == 0) {
    return Status(0, "OK");
  }

  /*
   * Pattern is '%%', grab everything.
   * Note that if '%%' is present but not at the end of the pattern,
   * then it is treated like a single glob.
   */
  if (boost::ends_with(pathElems[0], kSQLGlobRecursive) &&
      pathElems.size() == 1) {
    populateDefaultKeys(results);
    return populateAllKeysRecursive(results);
  }

  // Special handling to insert default keys when glob present in first elem
  if (pathElems[0].find(kSQLGlobWildcard) != std::string::npos) {
    populateDefaultKeys(results);
    pathElems.erase(pathElems.begin());
  } else {
    results.insert(pathElems[0]);
    pathElems.erase(pathElems.begin());
  }

  for (auto& elem = pathElems.begin(); elem != pathElems.end(); ++elem) {
    // We only care about  a recursive glob if it comes at the end of the
    // pattern i.e. 'HKEY_LOCAL_MACHINE\SOFTWARE\%%'
    if (boost::ends_with(*elem, kSQLGlobRecursive) &&
        *elem == pathElems.back()) {
      return populateAllKeysRecursive(results);
    } else if ((*elem).find(kSQLGlobWildcard) != std::string::npos) {
      populateSubkeys(results, true);
    } else {
      appendSubkeyToKeys(*elem, results);
    }
  }
  return Status(0, "OK");
}

static inline void maybeWarnLocalUsers(const std::set<std::string>& rKeys) {
  std::string hive, _;
  for (const auto& key : rKeys) {
    explodeRegistryPath(key, hive, _);
    if (hive == "HKEY_CURRENT_USER" ||
        hive == "HKEY_CURRENT_USER_LOCAL_SETTINGS") {
      LOG(WARNING) << "CURRENT_USER hives are not queryable by osqueryd; "
                      "query HKEY_USERS with the desired users SID instead";
      break;
    }
  }
}

QueryData genRegistry(QueryContext& context) {
  QueryData results;
  std::set<std::string> keys;

  if (!(context.hasConstraint("key", EQUALS) ||
        context.hasConstraint("key", LIKE))) {
    // We default to display all HIVEs
    expandRegistryGlobs(kSQLGlobWildcard, keys);
  } else {
    keys = context.constraints["key"].getAll(EQUALS);
    auto status = context.expandConstraints(
        "key",
        LIKE,
        keys,
        ([&](const std::string& pattern, std::set<std::string>& out) {
          std::set<std::string> resolvedKeys;
          auto status = expandRegistryGlobs(pattern, resolvedKeys);
          out.insert(resolvedKeys.begin(), resolvedKeys.end());
          return status;
        }));
    if (!status.ok()) {
      LOG(INFO) << "Failed to expand globs: " + status.getMessage();
    }
  }

  maybeWarnLocalUsers(keys);

  for (const auto& key : keys) {
    queryKey(key, results);
  }
  return results;
}
}
}
