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
#include <codecvt>
#include <locale>
#include <string>


namespace osquery {
namespace tables {
  
// we will be converting between UTF8 to UTF16-LE
static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::little_endian>> converter;

static std::wstring string_to_wstring(const std::string &src) {
  std::wstring utf16le_str = converter.from_bytes(src);
  return utf16le_str;
}

static std::string wstring_to_string(const wchar_t* src) {
  if (src == nullptr) {
    return std::string("");
  }

  std::string utf8_str = converter.to_bytes(src);
  return utf8_str;
}

static std::string BSTR_to_string(const BSTR src) {
  return wstring_to_string(static_cast<const wchar_t*>(src));
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

  while (SUCCEEDED(enum_->Next(WBEM_INFINITE, 1, &result, &result_count))) {
    // WmiResultItem will take ownership of result
    // and call result->Release() when it goes out of scope
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

