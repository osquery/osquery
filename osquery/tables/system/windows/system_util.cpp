/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/system/windows/system_util.h"

namespace osquery {
namespace tables {
  
static std::wstring string_to_wstring(const std::string &src) {
  std::vector<wchar_t> buffer;
  size_t new_size = src.size() + 1;

  buffer.assign(new_size, L'\0');

  size_t converted_chars = 0;

  // TODO(audit): Make sure this is doing the right thing
  if (::mbstowcs_s(&converted_chars, &buffer[0], new_size, src.c_str(),
                   _TRUNCATE) != 0) {
    return std::wstring(L"");
  }

  return std::wstring(buffer.begin(), buffer.end());
}

static std::string BSTR_to_string(const BSTR src) {
  if (src == nullptr) {
    return std::string("");
  }

  std::vector<char> buffer;

  // TODO(audit): Make sure this is doing the right thing
  int size =
      ::WideCharToMultiByte(CP_UTF8, 0, src, -1, nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    return std::string("");
  }

  buffer.assign(size, '\0');
  if (WideCharToMultiByte(CP_UTF8, 0, src, -1, &buffer[0], size, nullptr,
                          nullptr) == 0) {
    return std::string("");
  }

  return std::string(buffer.begin(), buffer.end());
}

WmiResultItem::WmiResultItem(WmiResultItem&& src) {
  result_ = nullptr;
  std::swap(result_, src.result_);
}

WmiResultItem::~WmiResultItem() {
  if (result_ != nullptr) {
    result_->Release();
    result_ = nullptr;
  }
}

void WmiResultItem::PrintType(const std::string& name) const {
  std::wstring property_name = string_to_wstring(name);

  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    std::cerr << "Failed: " << name << "\n";
  } else {
    std::cout << "Name=" << name << ", Type=" << value.vt << "\n";
    if (value.vt == VT_I4) {
      std::cout << "  Value=" << value.lVal << "\n";
    } else if (value.vt == VT_BSTR) {
      std::wcout << "  Value=" << value.bstrVal << "\n";
    }
  }
}

long WmiResultItem::GetLong(const std::string& name) const {
  std::wstring property_name = string_to_wstring(name);

  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK || value.vt != VT_I4) {
    return -1;
  }
  return value.lVal;
}

std::string WmiResultItem::GetString(const std::string& name) const {
  std::wstring property_name = string_to_wstring(name);

  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK || value.vt != VT_BSTR) {
    return std::string("");
  }
  return BSTR_to_string(value.bstrVal);
}

WmiRequest::WmiRequest(const std::string& query) {
  std::wstring wql = string_to_wstring(query);

  HRESULT hr = E_FAIL;

  hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);
  hr = ::CoInitializeSecurity(
    nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  hr = ::CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&locator_);
  if (hr != S_OK) {
    locator_ = nullptr;
    return;
  }

  hr = locator_->ConnectServer(L"ROOT\\CIMV2", nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services_);
  if (hr != S_OK) {
    services_ = nullptr;
    return;
  }

  hr = services_->ExecQuery(L"WQL", (BSTR)wql.c_str(), WBEM_FLAG_FORWARD_ONLY, nullptr, &enum_);
  if (hr != S_OK) {
    enum_ = nullptr;
    return;
  }

  IWbemClassObject *result = nullptr;
  ULONG result_count = 0;

  while (enum_->Next(WBEM_INFINITE, 1, &result, &result_count) == S_OK) {
    results_.push_back(WmiResultItem(result));
  }

  status_ = true;
}

WmiRequest::WmiRequest(WmiRequest&& src) {
  locator_ = nullptr;
  std::swap(locator_, src.locator_);

  services_ = nullptr;
  std::swap(services_, src.services_);

  enum_ = nullptr;
  std::swap(enum_, src.enum_);
}

WmiRequest::~WmiRequest() {
  results_.clear();

  if (enum_ != nullptr) {
    enum_->Release();
    enum_ = nullptr;
  }

  if (services_ != nullptr) {
    services_->Release();
    services_ = nullptr;
  }

  if (locator_ != nullptr) {
    locator_->Release();
    locator_ = nullptr;
  }

  ::CoUninitialize();
}
}
}