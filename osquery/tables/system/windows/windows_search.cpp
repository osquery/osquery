// osquery/tables/system/windows/windows_search.cpp

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atldbcli.h>
#include <codecvt>
#include <comutil.h>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <sstream>
#include <strsafe.h>
#include <vector>
#include <windows.h>

#pragma comment(lib, "comsuppw.lib")

namespace osquery {
namespace tables {

LONGLONG dateToUnixTime(const DATE date) {
  SYSTEMTIME st;
  FILETIME ft;

  VariantTimeToSystemTime(date, &st);
  SystemTimeToFileTime(&st, &ft);
  return filetimeToUnixtime(ft);
}

// This helper function can print some propvariants and handles BSTR vectors
void writePropVariant(REFPROPVARIANT variant, std::wstringstream& wss) {
  if (variant.vt == (VT_ARRAY | VT_BSTR) && variant.parray->cDims == 1) {
    BSTR* pBStr;
    HRESULT hr =
        SafeArrayAccessData(variant.parray, reinterpret_cast<void**>(&pBStr));
    if (SUCCEEDED(hr)) {
      for (unsigned int i = 0; i < variant.parray->rgsabound[0].cElements;
           i++) {
        if (i == 0) {
          wss << "[";
        } else {
          wss << ";";
        }
        wss << pBStr[i];
      }
      wss << "]";
      SafeArrayUnaccessData(variant.parray);
    } else {
      wss << "could not write vector";
    }
  } else {
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
}

std::string ccomandColumnStringValue(
    CCommand<CDynamicAccessor, CRowset>& cCommand, DBORDINAL columnIndex) {
  DBTYPE type;
  cCommand.GetColumnType(columnIndex, &type);

  std::wstringstream wss;

  DBSTATUS status;
  cCommand.GetStatus(columnIndex, &status);
  if (status == DBSTATUS_S_ISNULL) {
    wss << "NULL";
  } else if (status == DBSTATUS_S_OK || status == DBSTATUS_S_TRUNCATED) {
    DBTYPE type;
    cCommand.GetColumnType(columnIndex, &type);
    switch (type) {
    case DBTYPE_VARIANT:
      writePropVariant(
          *(static_cast<PROPVARIANT*>(cCommand.GetValue(columnIndex))), wss);
      break;
    case DBTYPE_WSTR: {
      DBLENGTH cbLen;
      cCommand.GetLength(columnIndex, &cbLen);
      WCHAR szBuffer[2048];
      StringCchCopyN(szBuffer,
                     ARRAYSIZE(szBuffer),
                     static_cast<WCHAR*>(cCommand.GetValue(columnIndex)),
                     cbLen / sizeof(WCHAR));
      wss << szBuffer;
    } break;
    case DBTYPE_I1:
      wss << *static_cast<UCHAR*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_UI2:
      wss << *static_cast<USHORT*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_I2:
      wss << *static_cast<SHORT*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_UI4:
      wss << *static_cast<DWORD*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_I4:
      wss << *static_cast<INT*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_UI8:
      wss << *static_cast<ULONGLONG*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_I8:
      wss << *static_cast<LONGLONG*>(cCommand.GetValue(columnIndex));
      break;
    case DBTYPE_DATE:
      wss << dateToUnixTime(
          *static_cast<DATE*>(cCommand.GetValue(columnIndex)));
      break;
    default:
      wss << "unhandled database type " << type;
      break;
    }
  } else {
    wss << "error reading column";
  }

  std::wstring wideStr = wss.str();
  std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
  return converter.to_bytes(wideStr);
}

std::vector<std::map<std::string, std::string>> executeWindowsSearchQuery(
    CSession& cSession, const std::string& query) {
  HRESULT hr;
  std::vector<std::map<std::string, std::string>> results;

  CCommand<CDynamicAccessor, CRowset> cCommand;
  hr = cCommand.Open(cSession, query.c_str());

  if (!SUCCEEDED(hr)) {
    LOG(ERROR) << "error executing query";
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

QueryData genWindowsSearch(QueryContext& context) {
  QueryData results;

  HRESULT hr = CoInitialize(NULL);

  CDataSource cDataSource;
  hr = cDataSource.OpenFromInitializationString(
      L"provider=Search.CollatorDSO.1;EXTENDED "
      L"PROPERTIES=\"Application=Windows\"");

  if (!SUCCEEDED(hr)) {
    LOG(ERROR) << "error initializing CDataSource";
    return results;
  }

  CSession cSession;
  hr = cSession.Open(cDataSource);

  if (!SUCCEEDED(hr)) {
    LOG(ERROR) << "error opening CSession";
    return results;
  }

  auto queries = context.constraints["query"].getAll(EQUALS);

  for (const auto& query : queries) {
    auto queryResults = executeWindowsSearchQuery(cSession, query);

    for (size_t i = 0; i < queryResults.size(); i++) {
      for (const auto& [key, value] : queryResults[i]) {
        Row r;
        r["entity"] = INTEGER(i);
        r["attribute"] = key;
        r["value"] = value;
        r["query"] = query;
        results.push_back(r);
      }
    }
  }

  cSession.Close();
  cDataSource.Close();
  CoUninitialize();
  return results;
}

} // namespace tables
} // namespace osquery
