/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/system.h>
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

#include <sqlite3.h>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/tables/system/windows/registry.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

auto closeRegHandle = [](HKEY handle) { RegCloseKey(handle); };
using reg_handle_t = std::unique_ptr<HKEY__, decltype(closeRegHandle)>;

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

const std::vector<std::string> kClassKeys = {
    "HKEY_USERS\\%\\SOFTWARE\\Classes\\CLSID",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID"};

const std::vector<std::string> kClassExecSubKeys = {
    "InProcServer%", "InProcHandler%", "LocalServer%"};

Status queryMultipleRegistryKeys(const std::vector<std::string>& regexes,
                                 const std::string& additionalConstraints,
                                 QueryData& results) {
  auto dbc = SQLiteDBManager::get();
  std::string query(
      "SELECT key, path, name, type, data, mtime FROM registry WHERE ");

  if (!additionalConstraints.empty()) {
    query += additionalConstraints + " AND ";
  }

  // Construct all of the registry key globs
  query += "(key LIKE ";
  std::vector<std::string> questions(regexes.size(), "?");
  query += osquery::join(questions, " OR key LIKE ");
  query += ")";

  sqlite3_stmt* stmt = nullptr;
  auto ret = sqlite3_prepare_v2(
      dbc->db(), query.c_str(), static_cast<int>(query.size()), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    return Status(1, "Failed to prepare sql query");
  }
  for (size_t i = 0; i < regexes.size(); i++) {
    sqlite3_bind_text(
        stmt, static_cast<int>(i + 1), regexes[i].c_str(), -1, SQLITE_STATIC);
  }

  // The registry table schema has exactly 6 columns
  if (sqlite3_column_count(stmt) != 6) {
    return Status(1, "registry query returned invalid number of columns");
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    Row r;
    r["key"] = SQL_TEXT(sqlite3_column_text(stmt, 0));
    r["path"] = SQL_TEXT(sqlite3_column_text(stmt, 1));
    r["name"] = SQL_TEXT(sqlite3_column_text(stmt, 2));
    r["type"] = SQL_TEXT(sqlite3_column_text(stmt, 3));
    r["data"] = SQL_TEXT(sqlite3_column_text(stmt, 4));
    r["mtime"] = BIGINT(sqlite3_column_int64(stmt, 5));
    results.push_back(r);
  }

  ret = sqlite3_finalize(stmt);
  if (ret != SQLITE_OK) {
    return Status(1,
                  "Failed to finalize statement with " + std::to_string(ret));
  }
  return Status::success();
}

Status getClassName(const std::string& clsId, std::string& rClsName) {
  std::vector<std::string> keys;
  for (const auto& key : kClassKeys) {
    keys.push_back(key + kRegSep + clsId);
  }

  QueryData regQueryResults;
  std::string constraint("name = '" + kDefaultRegName + "'");
  auto ret = queryMultipleRegistryKeys(keys, constraint, regQueryResults);

  if (!ret.ok()) {
    return ret;
  }
  if (regQueryResults.empty()) {
    return Status(1, "ClsId not found in registry");
  }

  for (const auto& row : regQueryResults) {
    if (!row.at("data").empty()) {
      rClsName = row.at("data");
      return Status::success();
    }
  }

  return Status(1, "No class name present in registry");
}

Status getClassExecutables(const std::string& clsId,
                           std::vector<std::string>& results) {
  std::vector<std::string> resolvedKeys;
  for (auto key : kClassKeys) {
    for (const auto& subkey : kClassExecSubKeys) {
      resolvedKeys.push_back(key + kRegSep + clsId + kRegSep + subkey);
    }
  }

  QueryData regQueryResults;
  auto ret = queryMultipleRegistryKeys(resolvedKeys, "", regQueryResults);
  if (!ret.ok()) {
    return ret;
  }
  if (regQueryResults.empty()) {
    return Status(1, "ClsId not found in registry");
  }

  for (const auto& r : regQueryResults) {
    if (r.at("name") == kDefaultRegName) {
      results.push_back(r.at("data"));
    }
  }
  return Status::success();
}

Status getUsernameFromKey(const std::string& key, std::string& rUsername) {
  if (!boost::starts_with(key, "HKEY_USERS")) {
    return Status(1, "Can not extract username from non-HKEY_USERS key");
  }

  auto toks = osquery::split(key, kRegSep);
  if (toks.size() < 2) {
    return Status(
        1, "Improperly-formatted HKEY_USERS key, cannot extract username");
  }

  PSID sid;
  if (!ConvertStringSidToSidA(toks[1].c_str(), &sid)) {
    return Status(GetLastError(), "Could not convert string to sid");
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
      return Status(GetLastError(), "Could not find sid");
    } else {
      rUsername = std::move(wstringToString(accntName));
    }
  }
  return Status::success();
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
Status queryKey(const std::string& keyPath, QueryData& results) {
  std::string hive;
  std::string key;
  explodeRegistryPath(keyPath, hive, key);

  if (kRegistryHives.count(hive) != 1) {
    return Status::success();
  }

  HKEY hkey;
  auto ret = RegOpenKeyEx(
      kRegistryHives.at(hive), TEXT(key.c_str()), 0, KEY_READ, &hkey);
  reg_handle_t hRegistryHandle(hkey, closeRegHandle);

  if (ret != ERROR_SUCCESS) {
    return Status(ret, "Failed to open registry handle");
  }

  const DWORD maxKeyLength = 255;
  const DWORD maxValueName = 16383;
  DWORD cSubKeys;
  DWORD cValues;
  DWORD cchMaxValueName;
  DWORD cbMaxValueData;
  DWORD retCode;
  FILETIME ftLastWriteTime;
  retCode = RegQueryInfoKey(hRegistryHandle.get(),
                            nullptr,
                            nullptr,
                            nullptr,
                            &cSubKeys,
                            nullptr,
                            nullptr,
                            &cValues,
                            &cchMaxValueName,
                            &cbMaxValueData,
                            nullptr,
                            &ftLastWriteTime);
  if (retCode != ERROR_SUCCESS) {
    return Status(retCode, "Failed to query registry info for key");
  }
  auto achKey = std::make_unique<TCHAR[]>(maxKeyLength);
  DWORD cbName;

  // Process registry subkeys
  if (cSubKeys > 0) {
    for (DWORD i = 0; i < cSubKeys; i++) {
      cbName = maxKeyLength;
      retCode = RegEnumKeyEx(hRegistryHandle.get(),
                             i,
                             achKey.get(),
                             &cbName,
                             nullptr,
                             nullptr,
                             nullptr,
                             &ftLastWriteTime);
      if (retCode != ERROR_SUCCESS) {
        return Status(retCode, "Failed to enumerate registry key");
      }

      Row r;
      r["key"] = keyPath;
      r["type"] = "subkey";
      r["name"] = achKey.get();
      r["path"] = keyPath + kRegSep + achKey.get();
      r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));
      results.push_back(r);
    }
  }

  if (cValues <= 0) {
    return Status::success();
  }

  DWORD cchValue = maxKeyLength;
  auto achValue = std::make_unique<TCHAR[]>(maxValueName);
  auto bpDataBuff = std::make_unique<BYTE[]>(cbMaxValueData);

  // Process registry values
  for (size_t i = 0; i < cValues; i++) {
    cchValue = maxValueName;
    achValue[0] = '\0';

    retCode = RegEnumValue(hRegistryHandle.get(),
                           static_cast<DWORD>(i),
                           achValue.get(),
                           &cchValue,
                           nullptr,
                           nullptr,
                           nullptr,
                           nullptr);
    if (retCode != ERROR_SUCCESS) {
      return Status(retCode, "Failed to enumerate registry values");
    }

    DWORD lpData = cbMaxValueData;
    DWORD lpType;

    retCode = RegQueryValueEx(hRegistryHandle.get(),
                              achValue.get(),
                              nullptr,
                              &lpType,
                              bpDataBuff.get(),
                              &lpData);
    if (retCode != ERROR_SUCCESS) {
      return Status(retCode, "Failed to query registry value");
    }

    // It's possible for registry entries to have been inserted incorrectly
    // resulting in non-null-terminated strings
    if (bpDataBuff != nullptr && lpData != 0 &&
        kRegistryStringTypes.find(lpType) != kRegistryStringTypes.end()) {
      bpDataBuff[lpData - 1] = 0x00;
    }

    Row r;
    r["key"] = keyPath;
    r["name"] = ((achValue[0] == '\0') ? "(Default)" : achValue.get());
    r["path"] = keyPath + kRegSep + achValue.get();
    if (kRegistryTypes.count(lpType) > 0) {
      r["type"] = kRegistryTypes.at(lpType);
    } else {
      r["type"] = "UNKNOWN";
    }
    r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));

    if (bpDataBuff != nullptr) {
      /// REG_LINK is a Unicode string, which in Windows is wchar_t
      auto regLinkStr = std::make_unique<char[]>(cbMaxValueData);
      if (lpType == REG_LINK) {
        const size_t newSize = cbMaxValueData;
        size_t convertedChars = 0;
        wcstombs_s(&convertedChars,
                   regLinkStr.get(),
                   newSize,
                   (wchar_t*)bpDataBuff.get(),
                   _TRUNCATE);
      }

      std::vector<char> regBinary;
      std::string data;
      std::vector<std::string> multiSzStrs;
      auto p = bpDataBuff.get();

      switch (lpType) {
      case REG_FULL_RESOURCE_DESCRIPTOR:
      case REG_RESOURCE_LIST:
      case REG_BINARY:
        for (size_t j = 0; j < cbMaxValueData; j++) {
          regBinary.push_back((char)bpDataBuff[j]);
        }
        boost::algorithm::hex(
            regBinary.begin(), regBinary.end(), std::back_inserter(data));
        r["data"] = data;
        break;
      case REG_DWORD:
        r["data"] = std::to_string(*((int*)bpDataBuff.get()));
        break;
      case REG_DWORD_BIG_ENDIAN:
        r["data"] = std::to_string(_byteswap_ulong(*((int*)bpDataBuff.get())));
        break;
      case REG_EXPAND_SZ:
        r["data"] = std::string((char*)bpDataBuff.get());
        break;
      case REG_LINK:
        r["data"] = std::string(regLinkStr.get());
        break;
      case REG_MULTI_SZ:
        while (*p != 0x00) {
          std::string s((char*)p);
          p += s.size() + 1;
          multiSzStrs.push_back(s);
        }
        r["data"] = boost::algorithm::join(multiSzStrs, ",");
        break;
      case REG_NONE:
        r["data"] = "(zero-length binary value)";
        break;
      case REG_QWORD:
        r["data"] = std::to_string(*((unsigned long long*)bpDataBuff.get()));
        break;
      case REG_SZ:
        r["data"] = std::string((char*)bpDataBuff.get());
        break;
      default:
        r["data"] = "";
        break;
      }
      ZeroMemory(bpDataBuff.get(), cbMaxValueData);
    }
    results.push_back(r);
  }
  return Status::success();
}

static inline void populateDefaultKeys(std::set<std::string>& rKeys) {
  boost::copy(kRegistryHives | boost::adaptors::map_keys,
              std::inserter(rKeys, rKeys.end()));
}

static inline Status populateSubkeys(std::set<std::string>& rKeys,
                                     bool replaceKeys = false) {
  std::set<std::string> newKeys;
  if (!replaceKeys) {
    newKeys = rKeys;
  }

  for (const auto& key : rKeys) {
    QueryData regResults;
    auto ret = queryKey(key, regResults);
    if (!ret.ok()) {
      return ret;
    }
    for (const auto& r : regResults) {
      if (r.at("type") == "subkey") {
        newKeys.insert(r.at("path"));
      }
    }
  }
  rKeys = std::move(newKeys);
  return Status::success();
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
  auto ret = populateSubkeys(rKeys);
  if (!ret.ok()) {
    return ret;
  }
  if (size_pre < rKeys.size()) {
    auto status = populateAllKeysRecursive(rKeys, ++currDepth);
    if (!status.ok()) {
      return status;
    }
  }

  return Status::success();
}

Status expandRegistryGlobs(const std::string& pattern,
                           std::set<std::string>& results) {
  auto pathElems = osquery::split(pattern, kRegSep);
  if (pathElems.size() == 0) {
    return Status::success();
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

  for (auto&& elem = pathElems.begin(); elem != pathElems.end(); ++elem) {
    // We only care about  a recursive glob if it comes at the end of the
    // pattern i.e. 'HKEY_LOCAL_MACHINE\SOFTWARE\%%'
    if (boost::ends_with(*elem, kSQLGlobRecursive) &&
        *elem == pathElems.back()) {
      return populateAllKeysRecursive(results);
    } else if ((*elem).find(kSQLGlobWildcard) != std::string::npos) {
      auto ret = populateSubkeys(results, true);
      if (!ret.ok()) {
        return ret;
      }
    } else {
      appendSubkeyToKeys(*elem, results);
    }
  }
  return Status::success();
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
        context.hasConstraint("key", LIKE) ||
        context.hasConstraint("path", EQUALS) ||
        context.hasConstraint("path", LIKE))) {
    // We default to display all HIVEs
    expandRegistryGlobs(kSQLGlobWildcard, keys);
  } else {
    if (context.hasConstraint("key", EQUALS)) {
      keys = context.constraints["key"].getAll(EQUALS);
    }
    if (context.hasConstraint("key", LIKE)) {
      for (const auto& key : context.constraints["key"].getAll(LIKE)) {
        auto status = expandRegistryGlobs(key, keys);
        if (!status.ok()) {
          LOG(INFO) << "Failed to expand globs: " + status.getMessage();
        }
      }
    }
    if (context.hasConstraint("path", EQUALS)) {
      for (const auto& path : context.constraints["path"].getAll(EQUALS)) {
        keys.insert(path.substr(0, path.find_last_of(kRegSep)));
      }
    }
    if (context.hasConstraint("path", LIKE)) {
      for (const auto& path : context.constraints["path"].getAll(LIKE)) {
        auto status = expandRegistryGlobs(
            path.substr(0, path.find_last_of(kRegSep)), keys);
        if (!status.ok()) {
          LOG(INFO) << "Failed to expand globs: " + status.getMessage();
        }
      }
    }
  }

  maybeWarnLocalUsers(keys);

  for (const auto& key : keys) {
    queryKey(key, results);
  }
  return results;
}
} // namespace tables
} // namespace osquery
