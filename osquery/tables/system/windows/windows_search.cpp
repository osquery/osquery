// osquery/tables/system/windows/windows_search.cpp

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Windows headers
#include <atlbase.h>
#include <atldbcli.h>
#include <comutil.h>
#include <searchapi.h>
#include <windows.h>

// standard library headers
#include <codecvt>
#include <sstream>
#include <strsafe.h>

// osquery headers
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

const std::string windowsSearchTableName = "windows_search";

LONGLONG dateToUnixTime(const DATE date) {
  SYSTEMTIME st = {0};
  FILETIME ft = {0};

  if (!VariantTimeToSystemTime(date, &st)) {
    LOG(ERROR) << windowsSearchTableName
               << ": failed to convert date to system time";
    return 0;
  }

  if (!SystemTimeToFileTime(&st, &ft)) {
    LOG(ERROR) << windowsSearchTableName
               << ": failed to convert system time to file time";
    return 0;
  }

  LONGLONG unixtime = filetimeToUnixtime(ft);
  if (unixtime == 0) {
    LOG(ERROR) << windowsSearchTableName
               << ": failed to convert file time to unix time";
    return 0;
  }

  return unixtime;
}

// This helper function can print some propvariants and handles BSTR vectors
void writePropVariant(REFPROPVARIANT variant, std::wstringstream& wss) {
  if (variant.vt == (VT_ARRAY | VT_BSTR) && variant.parray &&
      variant.parray->cDims == 1) {
    BSTR* pBStr = nullptr;
    HRESULT hr =
        SafeArrayAccessData(variant.parray, reinterpret_cast<void**>(&pBStr));

    if (FAILED(hr)) {
      LOG(ERROR) << windowsSearchTableName << ": SafeArrayAccessData failed";
      return;
    }

    for (unsigned int i = 0; i < variant.parray->rgsabound[0].cElements; i++) {
      if (i == 0) {
        wss << "[";
      } else {
        wss << ";";
      }
      wss << pBStr[i];
    }
    wss << "]";

    SafeArrayUnaccessData(variant.parray);
    return;
  }

  switch (variant.vt) {
  case VT_LPWSTR:
    wss << variant.pwszVal;
    break;
  case VT_BSTR:
    wss << variant.bstrVal;
    break;
  case VT_I1:
    wss << variant.cVal;
    break;
  case VT_UI2:
    wss << variant.uiVal;
    break;
  case VT_I2:
    wss << variant.iVal;
    break;
  case VT_UI4:
    wss << variant.ulVal;
    break;
  case VT_I4:
    wss << variant.lVal;
    break;
  case VT_UI8:
    wss << variant.uhVal.HighPart << variant.uhVal.LowPart;
    break;
  case VT_I8:
    wss << variant.hVal.HighPart << variant.hVal.LowPart;
    break;
  case VT_DATE:
    wss << dateToUnixTime(variant.date);
    break;
  default:
    wss << "unhandled variant type " << variant.vt;
    break;
  }
}

std::string ccomandColumnStringValue(
    CCommand<CDynamicAccessor, CRowset>& cCommand, DBORDINAL columnIndex) {
  DBTYPE type;
  cCommand.GetColumnType(columnIndex, &type);

  std::wstringstream wss;

  DBSTATUS status;
  cCommand.GetStatus(columnIndex, &status);
  switch (status) {
  case DBSTATUS_S_ISNULL: {
    wss << "NULL";
    break;
  }
  case DBSTATUS_S_OK:
  case DBSTATUS_S_TRUNCATED: {
    switch (type) {
    case DBTYPE_VARIANT: {
      writePropVariant(
          *(static_cast<PROPVARIANT*>(cCommand.GetValue(columnIndex))), wss);
      break;
    }
    case DBTYPE_WSTR: {
      DBLENGTH cbLen;
      cCommand.GetLength(columnIndex, &cbLen);
      WCHAR szBuffer[2048];
      StringCchCopyN(szBuffer,
                     ARRAYSIZE(szBuffer),
                     static_cast<WCHAR*>(cCommand.GetValue(columnIndex)),
                     cbLen / sizeof(WCHAR));
      wss << szBuffer;
      break;
    }
    case DBTYPE_I1: {
      wss << *static_cast<UCHAR*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_UI2: {
      wss << *static_cast<USHORT*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_I2: {
      wss << *static_cast<SHORT*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_UI4: {
      wss << *static_cast<DWORD*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_I4: {
      wss << *static_cast<INT*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_UI8: {
      wss << *static_cast<ULONGLONG*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_I8: {
      wss << *static_cast<LONGLONG*>(cCommand.GetValue(columnIndex));
      break;
    }
    case DBTYPE_DATE: {
      wss << dateToUnixTime(
          *static_cast<DATE*>(cCommand.GetValue(columnIndex)));
      break;
    }
    default: {
      wss << "unhandled database type " << type;
      break;
    }
    }
    break;
  }
  default: {
    wss << "error reading column";
    break;
  }
  }

  std::wstring wideStr = wss.str();
  std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
  return converter.to_bytes(wideStr);
}

osquery::QueryData executeWindowsSearchQuery(CSession& cSession,
                                             const std::string& query) {
  HRESULT hr = NULL;
  std::vector<std::map<std::string, std::string>> results;

  CCommand<CDynamicAccessor, CRowset> cCommand;
  hr = cCommand.Open(cSession, query.c_str());

  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": error executing query";
    return results;
  }

  for (hr = cCommand.MoveFirst(); S_OK == hr; hr = cCommand.MoveNext()) {
    std::map<std::string, std::string> row;

    for (DBORDINAL i = 1; i <= cCommand.GetColumnCount(); i++) {
      auto columnName = cCommand.GetColumnName(i);
      std::string columnNameStr = wstringToString(columnName);

      // Add the column name and value to the row map.
      row[columnNameStr] = ccomandColumnStringValue(cCommand, i);
    }

    results.push_back(row);
  }

  cCommand.Close();
  return results;
}

std::string generateSqlFromUserQuery(const std::string& userInput,
                                     std::set<std::string> columns,
                                     std::string sort,
                                     LONG maxResults) {
  HRESULT hr = NULL;

  // Create ISearchManager instance
  ISearchManager* pSearchManager = nullptr;
  // Use library SearchSDK.lib for CLSID_CSearchManager.
  hr = CoCreateInstance(CLSID_CSearchManager,
                        NULL,
                        CLSCTX_LOCAL_SERVER,
                        IID_PPV_ARGS(&pSearchManager));
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName
               << ": failed to create ISearchManager instance";
    return "";
  }
  auto const pSearchManagerGuard =
      scope_guard::create([pSearchManager]() { pSearchManager->Release(); });

  // Create ISearchCatalogManager instance
  ISearchCatalogManager* pSearchCatalogManager = nullptr;
  // Call ISearchManager::GetCatalog for "SystemIndex" to access the catalog to
  // the ISearchCatalogManager
  hr = pSearchManager->GetCatalog(L"SystemIndex", &pSearchCatalogManager);
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": failed to get catalog manager";
    return "";
  }
  auto const pSearchCatalogManagerGuard = scope_guard::create(
      [pSearchCatalogManager]() { pSearchCatalogManager->Release(); });

  // Call ISearchCatalogManager::GetQueryHelper to get the ISearchQueryHelper
  // interface
  ISearchQueryHelper* pQueryHelper = nullptr;
  hr = pSearchCatalogManager->GetQueryHelper(&pQueryHelper);
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": failed to get query helper";
    return "";
  }
  auto const pQueryHelperGuard =
      scope_guard::create([pQueryHelper]() { pQueryHelper->Release(); });

  hr = pQueryHelper->put_QueryMaxResults(maxResults);
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": failed to set max results";
    return "";
  }

  if (!columns.empty()) {
    // TODO: find a way to verify that the columns requested exist before the
    // query else we just get an error. If a new column is added or dropped on
    // an OS could break existing queries.
    std::string selectColumns;
    for (const auto& k : columns) {
      selectColumns += k + ",";
    }

    // Remove the last comma
    if (!selectColumns.empty()) {
      selectColumns.pop_back();
    }

    hr = pQueryHelper->put_QuerySelectColumns(
        stringToWstring(selectColumns).c_str());
    if (FAILED(hr)) {
      LOG(ERROR) << windowsSearchTableName << ": failed to set columns";
      return "";
    }
  }

  if (!sort.empty()) {
    hr = pQueryHelper->put_QuerySorting(stringToWstring(sort).c_str());
    if (FAILED(hr)) {
      LOG(ERROR) << windowsSearchTableName << ": failed to set sort";
      return "";
    }
  }

  LPWSTR sql;
  hr = pQueryHelper->GenerateSQLFromUserQuery(
      stringToWstring(userInput).c_str(), &sql);
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName
               << ": failed to generate SQL from user query";
    return "";
  }

  std::string ret = wstringToString(sql);
  CoTaskMemFree(sql);
  return ret;
}

QueryData genWindowsSearch(QueryContext& context) {
  QueryData results;
  HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
  auto const coUninitalizeGuard =
      scope_guard::create([hr]() { CoUninitialize(); });

  CDataSource cDataSource;
  hr = cDataSource.OpenFromInitializationString(
      L"provider=Search.CollatorDSO.1;EXTENDED "
      L"PROPERTIES=\"Application=Windows\"");
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": error initializing CDataSource";
    return results;
  }
  auto const cDataSourceGuard =
      scope_guard::create([&cDataSource]() { cDataSource.Close(); });

  CSession cSession;
  hr = cSession.Open(cDataSource);
  if (FAILED(hr)) {
    LOG(ERROR) << windowsSearchTableName << ": error opening CSession";
    return results;
  }
  auto const cSessionGuard =
      scope_guard::create([&cSession]() { cSession.Close(); });

  LONG maxResults = 100;
  if (context.hasConstraint("max_results", EQUALS)) {
    auto maxResultsConstraint =
        context.constraints["max_results"].getAll(EQUALS);
    auto maxResultsStr = SQL_TEXT(*maxResultsConstraint.begin());
    maxResults = std::stol(maxResultsStr);
  }

  class windowsToOsqueryColumn {
   public:
    std::string osqueryColumnName;
    std::string osqueryColumnType;
  };

  std::map<std::string, windowsToOsqueryColumn>
      defaultWindowsPropertiesToOsqueryColumns = {
          {"system.itemname", {"name", "TEXT"}},
          {"system.itempathdisplay", {"path", "TEXT"}},
          {"system.size", {"size", "INTEGER"}},
          {"system.datecreated", {"date_created", "INTEGER"}},
          {"system.datemodified", {"date_modified", "INTEGER"}},
          {"system.fileowner", {"owner", "TEXT"}},
          {"system.itemtype", {"type", "TEXT"}},
      };

  // this set is what gets passed to query generator func to populate select
  // columns
  std::set<std::string> allProperties;
  for (const auto& kv : defaultWindowsPropertiesToOsqueryColumns) {
    allProperties.insert(kv.first);
  }

  std::string userInputAdditionalProperties = "";
  if (context.hasConstraint("additional_properties", EQUALS)) {
    auto additionalPropertiesConstraint =
        context.constraints["additional_properties"].getAll(EQUALS);
    userInputAdditionalProperties =
        SQL_TEXT(*additionalPropertiesConstraint.begin());

    // include the user defined additional properties in all properties
    for (const auto& v : osquery::split(userInputAdditionalProperties, ",")) {
      allProperties.insert(v);
    }
  }

  std::string sort = "";
  if (context.hasConstraint("sort", EQUALS)) {
    auto sortConstraint = context.constraints["sort"].getAll(EQUALS);
    sort = SQL_TEXT(*sortConstraint.begin());
  }

  std::string query = "*";
  if (context.hasConstraint("query", EQUALS)) {
    auto queryContext = context.constraints["query"].getAll(EQUALS);
    query = SQL_TEXT(*queryContext.begin());
  }

  auto generatedQuery =
      generateSqlFromUserQuery(query, allProperties, sort, maxResults);
  auto queryResults = executeWindowsSearchQuery(cSession, generatedQuery);

  for (size_t i = 0; i < queryResults.size(); i++) {
    Row r;
    r["sort"] = sort;
    r["max_results"] = INTEGER(maxResults);
    r["query"] = query;
    r["additional_properties"] = userInputAdditionalProperties;

    auto additionalPropertiesJson = JSON::newObject();

    for (const auto& [key, value] : queryResults[i]) {
      // if the property is not found in all properties, it's neither
      // a default nor user defined, so don't include in results
      // these can be added by the query
      if (!allProperties.count(key)) {
        continue;
      }

      // property was requested by user
      if (!defaultWindowsPropertiesToOsqueryColumns.count(key)) {
        additionalPropertiesJson.add(key, value);
        continue;
      }

      // default integer
      if (defaultWindowsPropertiesToOsqueryColumns[key].osqueryColumnType ==
          "INTEGER") {
        r[defaultWindowsPropertiesToOsqueryColumns[key].osqueryColumnName] =
            INTEGER(value);
        continue;
      }

      // default string
      r[defaultWindowsPropertiesToOsqueryColumns[key].osqueryColumnName] =
          SQL_TEXT(value);
    }

    std::string jsonString = "";
    additionalPropertiesJson.toString(jsonString);
    // if we got an empty json object just
    // set column to empty string
    if (jsonString == "{}") {
      jsonString = "";
    }
    r["properties"] = jsonString;

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery
