/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include "windows_update_history.h"

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {
namespace tables {

// Implementation
namespace {

const std::unordered_map<WindowsUpdateHistoryError, std::string>
    kWindowsUpdateHistoryErrorDescriptions{
        {WindowsUpdateHistoryError::UpdateSearcherError,
         "Failed to instantiate IUpdateSearcher"},
        {WindowsUpdateHistoryError::CountError,
         "Failed to get total update history count"},
        {WindowsUpdateHistoryError::QueryError,
         "Failed to query update history"},
        {WindowsUpdateHistoryError::SizeError,
         "Failed to get update history entry collection size"},
        {WindowsUpdateHistoryError::EntryError,
         "Failed to get update history entry"},
        {WindowsUpdateHistoryError::ClientApplicationIDError,
         "Failed to get history entry client application id"},
        {WindowsUpdateHistoryError::DateError,
         "Failed to get history entry date"},
        {WindowsUpdateHistoryError::DescriptionError,
         "Failed to get history entry description"},
        {WindowsUpdateHistoryError::HResultError,
         "Failed to get history entry HResult"},
        {WindowsUpdateHistoryError::OperationError,
         "Failed to get history entry operation"},
        {WindowsUpdateHistoryError::ResultCodeError,
         "Failed to get history entry result code"},
        {WindowsUpdateHistoryError::ServerSelectionError,
         "Failed to get history entry server selection"},
        {WindowsUpdateHistoryError::ServiceIDError,
         "Failed to get history entry service id"},
        {WindowsUpdateHistoryError::SupportURLError,
         "Failed to get history entry support URL"},
        {WindowsUpdateHistoryError::TitleError,
         "Failed to get history entry title"},
        {WindowsUpdateHistoryError::IdentityError,
         "Failed to get history entry identity"},
        {WindowsUpdateHistoryError::UpdateIDError,
         "Failed to get history entry update id"},
        {WindowsUpdateHistoryError::UpdateRevisionError,
         "Failed to get history entry update revision"},
    };

std::string getErrorDescription(const WindowsUpdateHistoryError& error) {
  auto it = kWindowsUpdateHistoryErrorDescriptions.find(error);
  if (it == kWindowsUpdateHistoryErrorDescriptions.end()) {
    std::stringstream stream;
    stream << "Unknown error type: 0x" << std::hex
           << static_cast<std::uint64_t>(error);

    return stream.str();
  }

  return it->second;
}

Expected<WindowsUpdateHistoryEntry, WindowsUpdateHistoryError>
createWindowsUpdateHistoryEntryError(WindowsUpdateHistoryError error,
                                     HRESULT hr) {
  return createError(error)
         << getErrorDescription(error) << ", HRESULT=0x" << std::hex << hr;
}

Expected<WindowsUpdateHistory, WindowsUpdateHistoryError>
createWindowsUpdateHistoryError(WindowsUpdateHistoryError error, HRESULT hr) {
  return createError(error)
         << getErrorDescription(error) << ", HRESULT=0x" << std::hex << hr;
}

Row renderWindowsUpdateHistoryEntry(const WindowsUpdateHistoryEntry& entry) {
  Row r;
  r["client_app_id"] = entry.clientAppID;
  r["date"] = BIGINT(entry.date);
  r["description"] = entry.description;
  r["hresult"] = BIGINT(entry.hresult);

  switch (entry.updateOp) {
  case uoInstallation:
    r["operation"] = "Installation";
    break;
  case uoUninstallation:
    r["operation"] = "Uninstallation";
    break;
  default:
    r["operation"] = "";
    break;
  }

  switch (entry.resultCode) {
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
  default:
    r["result_code"] = "";
    break;
  }

  switch (entry.serverSelection) {
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
  default:
    r["server_selection"] = "";
    break;
  }

  r["service_id"] = entry.serviceID;
  r["support_url"] = entry.supportUrl;
  r["title"] = entry.title;
  r["update_id"] = entry.updateID;
  r["update_revision"] = BIGINT(entry.updateRevision);

  return r;
}

template <typename TClass>
using TBTRFunc = HRESULT (STDMETHODCALLTYPE TClass::*)(BSTR*);

template <typename TClass, typename TBTRFunc>
HRESULT getString(TClass* p, TBTRFunc fn, std::string& s) {
  HRESULT hr = S_OK;

  BSTR bstr = nullptr;
  if (SUCCEEDED(hr = (p->*fn)(&bstr))) {
    s = bstrToString(bstr);
  }
  SysFreeString(bstr);

  return hr;
}

template <typename T>
struct InterfaceReleaser final {
  void operator()(T* p) {
    if (p != nullptr) {
      p->Release();
    }
  }
};

Expected<WindowsUpdateHistoryEntry, WindowsUpdateHistoryError>
populateWindowsUpdateHistoryEntry(IUpdateHistoryEntry* entry) {
  WindowsUpdateHistoryEntry r;
  HRESULT hr = S_OK;

  if (FAILED(hr = getString(entry,
                            &IUpdateHistoryEntry::get_ClientApplicationID,
                            r.clientAppID))) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::ClientApplicationIDError, hr);
  }

  DATE date = 0;
  SYSTEMTIME st = {0};
  FILETIME ft = {0};
  FILETIME locFt = {0};

  hr = entry->get_Date(&date);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::DateError, hr);
  }
  VariantTimeToSystemTime(date, &st);
  SystemTimeToFileTime(&st, &ft);
  LocalFileTimeToFileTime(&ft, &locFt);
  r.date = filetimeToUnixtime(locFt);

  if (FAILED(hr = getString(entry,
                            &IUpdateHistoryEntry::get_Description,
                            r.description))) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::DescriptionError, hr);
  }

  hr = entry->get_HResult(&r.hresult);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::HResultError, hr);
  }

  hr = entry->get_Operation(&r.updateOp);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::OperationError, hr);
  }

  hr = entry->get_ResultCode(&r.resultCode);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::ResultCodeError, hr);
  }

  hr = entry->get_ServerSelection(&r.serverSelection);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::ServerSelectionError, hr);
  }

  if (r.serverSelection == ssOthers) {
    if (FAILED(hr = getString(
                   entry, &IUpdateHistoryEntry::get_ServiceID, r.serviceID))) {
      return createWindowsUpdateHistoryEntryError(
          WindowsUpdateHistoryError::ServiceIDError, hr);
    }
  }

  if (FAILED(hr = getString(
                 entry, &IUpdateHistoryEntry::get_SupportUrl, r.supportUrl))) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::SupportURLError, hr);
  }

  if (FAILED(hr = getString(entry, &IUpdateHistoryEntry::get_Title, r.title))) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::TitleError, hr);
  }

  IUpdateIdentity* pUpdateIdentity = nullptr;
  hr = entry->get_UpdateIdentity(&pUpdateIdentity);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::IdentityError, hr);
  }

  std::unique_ptr<IUpdateIdentity, InterfaceReleaser<IUpdateIdentity>>
      updateIdentity(pUpdateIdentity, InterfaceReleaser<IUpdateIdentity>());

  if (FAILED(hr = getString(pUpdateIdentity,
                            &IUpdateIdentity::get_UpdateID,
                            r.updateID))) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::UpdateIDError, hr);
  }

  hr = updateIdentity->get_RevisionNumber(&r.updateRevision);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::UpdateRevisionError, hr);
  }

  return r;
}

Expected<WindowsUpdateHistoryEntry, WindowsUpdateHistoryError> getAt(
    IUpdateHistoryEntryCollection* col, LONG idx) {
  IUpdateHistoryEntry* pEntry = nullptr;

  HRESULT hr = col->get_Item(idx, &pEntry);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryEntryError(
        WindowsUpdateHistoryError::EntryError, hr);
  }

  std::unique_ptr<IUpdateHistoryEntry, InterfaceReleaser<IUpdateHistoryEntry>>
      entry(pEntry, InterfaceReleaser<IUpdateHistoryEntry>());
  return populateWindowsUpdateHistoryEntry(pEntry);
}

Expected<WindowsUpdateHistory, WindowsUpdateHistoryError>
getWindowsUpdateHistory(QueryContext& context) {
  IUpdateSearcher* pUpdateSearcher = nullptr;
  HRESULT hr = CoCreateInstance(__uuidof(UpdateSearcher),
                                NULL,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&pUpdateSearcher));

  if (FAILED(hr)) {
    return createWindowsUpdateHistoryError(
        WindowsUpdateHistoryError::UpdateSearcherError, hr);
  }

  std::unique_ptr<IUpdateSearcher, InterfaceReleaser<IUpdateSearcher>>
      updateSearcher(pUpdateSearcher, InterfaceReleaser<IUpdateSearcher>());

  LONG totalCount = 0;
  hr = updateSearcher->GetTotalHistoryCount(&totalCount);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryError(
        WindowsUpdateHistoryError::CountError, hr);
  }

  IUpdateHistoryEntryCollection* pUpdateHistoryEntryCollection = nullptr;
  hr = updateSearcher->QueryHistory(
      0, totalCount, &pUpdateHistoryEntryCollection);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryError(
        WindowsUpdateHistoryError::QueryError, hr);
  }

  std::unique_ptr<IUpdateHistoryEntryCollection,
                  InterfaceReleaser<IUpdateHistoryEntryCollection>>
      updateHistoryEntryCollection(
          pUpdateHistoryEntryCollection,
          InterfaceReleaser<IUpdateHistoryEntryCollection>());

  LONG count = 0;
  hr = updateHistoryEntryCollection->get_Count(&count);
  if (FAILED(hr)) {
    return createWindowsUpdateHistoryError(WindowsUpdateHistoryError::SizeError,
                                           hr);
  }

  WindowsUpdateHistory results;
  for (LONG i = 0; i < count; i++) {
    auto res = getAt(pUpdateHistoryEntryCollection, i);
    if (res.isError()) {
      return res.takeError();
    }
    results.push_back(std::move(res.get()));
  }
  return results;
}

} // namespace

QueryData renderWindowsUpdateHistory(const WindowsUpdateHistory& history) {
  QueryData results;
  std::for_each(history.cbegin(),
                history.cend(),
                [&](const WindowsUpdateHistoryEntry& entry) {
                  results.push_back(renderWindowsUpdateHistoryEntry(entry));
                });
  return results;
}

QueryData genWindowsUpdateHistory(QueryContext& context) {
  auto r = getWindowsUpdateHistory(context);
  if (r.isError()) {
    TLOG << "Failed to get windows update history: "
         << r.getError().getMessage();
    return QueryData();
  }
  return renderWindowsUpdateHistory(r.get());
}

} // namespace tables
} // namespace osquery
