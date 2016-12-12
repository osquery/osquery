/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <locale>
#include <string>

#include "osquery/core/windows/wmi.h"

namespace osquery {

std::wstring stringToWstring(const std::string& src) {
  std::wstring utf16le_str = converter.from_bytes(src);
  return utf16le_str;
}

std::string wstringToString(const wchar_t* src) {
  if (src == nullptr) {
    return std::string("");
  }

  std::string utf8_str = converter.to_bytes(src);
  return utf8_str;
}

std::string bstrToString(const BSTR src) {
  return wstringToString(static_cast<const wchar_t*>(src));
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
  std::wstring property_name = stringToWstring(name);
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
  VariantClear(&value);
}

Status WmiResultItem::GetBool(const std::string& name, bool& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);

  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_BOOL) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.boolVal == VARIANT_TRUE ? true : false;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetUChar(const std::string& name,
                               unsigned char& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_UI1) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.bVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetLong(const std::string& name, long& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_I4) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.lVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetUnsignedLong(const std::string& name,
                                      unsigned long& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_UI4) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.lVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetLongLong(const std::string& name,
                                  long long& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_I8) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.lVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetUnsignedLongLong(const std::string& name,
                                          unsigned long long& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_UI8) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.lVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetString(const std::string& name,
                                std::string& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    ret = "";
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_BSTR) {
    ret = "";
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = bstrToString(value.bstrVal);
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetVectorOfStrings(const std::string& name,
                                         std::vector<std::string>& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != (VT_BSTR | VT_ARRAY)) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  long lbound, ubound;
  SafeArrayGetLBound(value.parray, 1, &lbound);
  SafeArrayGetUBound(value.parray, 1, &ubound);
  long count = ubound - lbound + 1;

  BSTR* pData = nullptr;
  SafeArrayAccessData(value.parray, (void**)&pData);
  ret.reserve(count);
  for (long i = 0; i < count; i++) {
    ret.push_back(bstrToString(pData[i]));
  }
  SafeArrayUnaccessData(value.parray);
  VariantClear(&value);
  return Status(0);
}

WmiRequest::WmiRequest(const std::string& query, BSTR nspace) {
  std::wstring wql = stringToWstring(query);

  HRESULT hr = E_FAIL;

  hr = ::CoInitializeSecurity(nullptr,
                              -1,
                              nullptr,
                              nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr,
                              EOAC_NONE,
                              nullptr);
  hr = ::CoCreateInstance(CLSID_WbemLocator,
                          0,
                          CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator,
                          (LPVOID*)&locator_);
  if (hr != S_OK) {
    locator_ = nullptr;
    return;
  }

  hr = locator_->ConnectServer(
      nspace, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services_);
  if (hr != S_OK) {
    services_ = nullptr;
    return;
  }

  hr = services_->ExecQuery(
      (BSTR)L"WQL", (BSTR)wql.c_str(), WBEM_FLAG_FORWARD_ONLY, nullptr, &enum_);
  if (hr != S_OK) {
    enum_ = nullptr;
    return;
  }

  hr = WBEM_S_NO_ERROR;
  while (hr == WBEM_S_NO_ERROR) {
    IWbemClassObject* result = nullptr;
    ULONG result_count = 0;

    hr = enum_->Next(WBEM_INFINITE, 1, &result, &result_count);
    if (SUCCEEDED(hr) && result_count > 0) {
      results_.push_back(WmiResultItem(result));
    }
  }

  status_ = Status(0);
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
}
}
