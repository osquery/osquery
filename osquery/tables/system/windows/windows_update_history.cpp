/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <atlbase.h>
#include <windows.h>
#include <wuapi.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {
namespace tables {

HRESULT populateRow(IUpdateHistoryEntry* entry, Row& r);

QueryData genUpdateHistory(QueryContext& context) {
  QueryData results;

  CComPtr<IUpdateSearcher> updateSearcher;
  HRESULT hr = updateSearcher.CoCreateInstance(CLSID_UpdateSearcher);
  if (FAILED(hr)) {
    TLOG << "Failed to instantiate IUpdateSearcher";
    return results;
  }

  LONG totalCount = 0;
  hr = updateSearcher->GetTotalHistoryCount(&totalCount);
  if (FAILED(hr)) {
    TLOG << "Failed to get total update history count";
    return results;
  }

  CComPtr<IUpdateHistoryEntryCollection> updateHistoryEntryCollection;
  hr = updateSearcher->QueryHistory(
      0, totalCount, &updateHistoryEntryCollection);
  if (FAILED(hr)) {
    TLOG << "Failed to query update history";
    return results;
  }

  LONG count = 0;
  hr = updateHistoryEntryCollection->get_Count(&count);
  if (FAILED(hr)) {
    TLOG << "Failed to get update history entry collection size";
    return results;
  }

  for (LONG i = 0; i < count; i++) {
    CComPtr<IUpdateHistoryEntry> entry;
    hr = updateHistoryEntryCollection->get_Item(i, &entry);
    if (FAILED(hr)) {
      TLOG << "Failed to get update history entry";
      return results;
    }
    Row r;
    hr = populateRow(entry, r);
    if (FAILED(hr)) {
      TLOG << "Failed to populate result row from update history entry";
      return results;
    }
    results.push_back(std::move(r));
  }

  return results;
}

HRESULT populateRow(IUpdateHistoryEntry* entry, Row& r) {
  HRESULT hr = S_OK;

  CComBSTR appID;
  hr = entry->get_ClientApplicationID(&appID);
  if (FAILED(hr)) {
    return hr;
  }
  r["client_app_id"] = bstrToString(appID);

  DATE date = 0;
  SYSTEMTIME st;
  FILETIME ft;
  FILETIME locFt;

  hr = entry->get_Date(&date);
  if (FAILED(hr)) {
    return hr;
  }
  VariantTimeToSystemTime(date, &st);
  SystemTimeToFileTime(&st, &ft);
  LocalFileTimeToFileTime(&ft, &locFt);
  r["date"] = BIGINT(filetimeToUnixtime(locFt));

  CComBSTR desc;
  hr = entry->get_Description(&desc);
  if (FAILED(hr)) {
    return hr;
  }
  r["description"] = bstrToString(desc);

  LONG hresult = 0;
  hr = entry->get_HResult(&hresult);
  if (FAILED(hr)) {
    return hr;
  }
  r["hresult"] = BIGINT(hresult);

  UpdateOperation updateOp;
  hr = entry->get_Operation(&updateOp);
  if (FAILED(hr)) {
    return hr;
  }
  switch (updateOp) {
  case uoInstallation:
    r["operation"] = "Installation";
    break;
  case uoUninstallation:
    r["operation"] = "Uninstallation";
    break;
  }

  OperationResultCode resultCode;
  hr = entry->get_ResultCode(&resultCode);
  if (FAILED(hr)) {
    return hr;
  }
  switch (resultCode) {
  case orcNotStarted:
    r["result_code"] = "NotStarted";
    break;
  case orcInProgress:
    r["result_code"] = "InProgress";
    break;
  case orcSucceeded:
    r["result_code"] = "Succeeded";
    break;
  case orcSucceededWithErrors:
    r["result_code"] = "SucceededWithErrors";
    break;
  case orcFailed:
    r["result_code"] = "Failed";
    break;
  case orcAborted:
    r["result_code"] = "Aborted";
    break;
  }

  ServerSelection serverSelection;
  hr = entry->get_ServerSelection(&serverSelection);
  if (FAILED(hr)) {
    return hr;
  }
  switch (serverSelection) {
  case ssDefault:
    r["server_selection"] = "Default";
    break;
  case ssManagedServer:
    r["server_selection"] = "ManagedServer";
    break;
  case ssWindowsUpdate:
    r["server_selection"] = "WindowsUpdate";
    break;
  case ssOthers:
    r["server_selection"] = "Others";
    break;
  }

  if (serverSelection == ssOthers) {
    CComBSTR serviceID;
    hr = entry->get_ServiceID(&serviceID);
    if (FAILED(hr)) {
      return hr;
    }
    r["service_id"] = bstrToString(serviceID);
  }

  CComBSTR supportUrl;
  hr = entry->get_SupportUrl(&supportUrl);
  if (FAILED(hr)) {
    return hr;
  }
  r["support_url"] = bstrToString(supportUrl);

  CComBSTR title;
  hr = entry->get_Title(&title);
  if (FAILED(hr)) {
    return hr;
  }
  r["title"] = bstrToString(title);

  CComPtr<IUpdateIdentity> updateIdentity;
  hr = entry->get_UpdateIdentity(&updateIdentity);
  if (FAILED(hr)) {
    return hr;
  }

  CComBSTR updateID;
  hr = updateIdentity->get_UpdateID(&updateID);
  if (FAILED(hr)) {
    return hr;
  }
  r["update_id"] = bstrToString(updateID);

  LONG revision;
  hr = updateIdentity->get_RevisionNumber(&revision);
  if (FAILED(hr)) {
    return hr;
  }
  r["update_revision"] = BIGINT(revision);

  return hr;
}

} // namespace tables
} // namespace osquery
