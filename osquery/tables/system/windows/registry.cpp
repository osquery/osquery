/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdlib.h>

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iterator>
#include <map>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

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

const std::string kRegSep = "\\";

void explodeRegistryPath(const std::string& path,
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

  BYTE* bpDataBuff = new BYTE[cbMaxValueData];
  DWORD cchValue = maxKeyLength;
  TCHAR achValue[maxValueName];

  // Process registry values
  for (size_t i = 0, retCode = ERROR_SUCCESS; i < cValues; i++) {
    size_t cnt = 0;
    ZeroMemory(bpDataBuff, cbMaxValueData);
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

    bpDataBuff[cbMaxValueData - 1] = 0x00;

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
      for (unsigned int i = 0; i < cbMaxValueData; i++) {
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
      r["data"] = std::string((char*)bpDataBuff);
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
    results.push_back(r);
    if (regLinkStr != nullptr) {
      delete[](regLinkStr);
    }
  }
  delete[](bpDataBuff);
  RegCloseKey(hRegistryHandle);
}


Status resolveRegistryGlobs(const std::string& pattern, std::vector<std::string> results) {
  return Status(0, "OK");
}

void maybeWarnLocalUsers(std::set<std::string>& keys) {
  std::string hive, _;
  for (const auto& key : keys) {
    explodeRegistryPath(key, hive, _);
    if (hive == "HKEY_CURRENT_USER" ||
        hive == "HKEY_CURRENT_USER_LOCAL_SETTINGS") {
      LOG(WARNING) << "CURRENT_USER hives are not queryable by osqueryd; "
                      "query HKEY_USERS with the desired users SID instead";
      return;
    }
  }
}

QueryData genRegistry(QueryContext& context) {
  QueryData results;
  std::set<std::string> keys;

  if (context.constraints["key"].exists(EQUALS)) {
    auto keys = context.constraints["key"].getAll(EQUALS);
  }
  context.expandConstraints(
    "key",
    LIKE,
    keys,
    ([&](const std::string& pattern, std::set<std::string>& out) {
      std::vector<std::string> resolvedKeys;
      auto status = resolveRegistryGlobs(pattern, resolvedKeys);
      if (status.ok()) {
        for (const auto& rk : resolvedKeys) {
          out.insert(rk);
        }
      }
      return status;
  }));

  /// By default, we display all HIVEs
  if (context.constraints.empty() && keys.empty()) {
    for (auto& h : kRegistryHives) {
      keys.insert(h.first);
    }
  }

  for (const auto& key : keys) {
    queryKey(key, results);
  }
  return results;
}
}
}
