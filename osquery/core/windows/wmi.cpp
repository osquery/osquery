/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <locale>
#include <string>

#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

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

Status WmiResultItem::GetDateTime(const std::string& name,
                                  bool is_local,
                                  FILETIME& ft) const {
  std::wstring property_name = stringToWstring(name);

  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);
  if (hr != S_OK) {
    return Status(-1, "Error retrieving datetime from WMI query result.");
  }

  if (value.vt != VT_BSTR) {
    VariantClear(&value);
    return Status(-1, "Expected VT_BSTR, got something else.");
  }

  ISWbemDateTime* dt = nullptr;
  hr = CoCreateInstance(
      CLSID_SWbemDateTime, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dt));
  if (!SUCCEEDED(hr)) {
    VariantClear(&value);
    return Status(-1, "Failed to create SWbemDateTime object.");
  }

  hr = dt->put_Value(value.bstrVal);
  VariantClear(&value);

  if (!SUCCEEDED(hr)) {
    dt->Release();
    return Status(-1, "Failed to set SWbemDateTime value.");
  }

  BSTR filetime_str = {0};
  hr = dt->GetFileTime(is_local ? VARIANT_TRUE : VARIANT_FALSE, &filetime_str);
  if (!SUCCEEDED(hr)) {
    dt->Release();
    return Status(-1, "GetFileTime failed.");
  }

  ULARGE_INTEGER ui = {};

  ui.QuadPart = _wtoi64(filetime_str);
  ft.dwLowDateTime = ui.LowPart;
  ft.dwHighDateTime = ui.HighPart;

  SysFreeString(filetime_str);
  dt->Release();

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

Status WmiResultItem::GetUnsignedShort(const std::string& name,
                                       unsigned short& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);

  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_UI2) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.uiVal;
  VariantClear(&value);
  return Status(0);
}

Status WmiResultItem::GetUnsignedInt32(const std::string& name,
                                       unsigned int& ret) const {
  std::wstring property_name = stringToWstring(name);
  VARIANT value;
  HRESULT hr = result_->Get(property_name.c_str(), 0, &value, nullptr, nullptr);

  if (hr != S_OK) {
    return Status(-1, "Error retrieving data from WMI query.");
  }
  if (value.vt != VT_UINT) {
    VariantClear(&value);
    return Status(-1, "Invalid data type returned.");
  }
  ret = value.uiVal;
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

  IWbemLocator *locator = nullptr;
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
                          (LPVOID*)&locator);
  if (hr != S_OK) {
    return;
  }

  locator_.reset(locator);

  IWbemServices *services = nullptr;
  hr = locator_->ConnectServer(
      nspace, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
  if (hr != S_OK) {
    return;
  }

  services_.reset(services);

  IEnumWbemClassObject *wbem_enum = nullptr;

  hr = services_->ExecQuery(
      (BSTR)L"WQL", (BSTR)wql.c_str(), WBEM_FLAG_FORWARD_ONLY, nullptr, &wbem_enum);
  if (hr != S_OK) {
    return;
  }

  enum_.reset(wbem_enum);

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

WmiRequest::~WmiRequest() {
  results_.clear();
}
}
