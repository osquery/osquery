/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <windows.h>
#include <iwscapi.h>
#include <wscapi.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {
namespace tables {

const auto kSecurityProviders = std::unordered_map<int, std::string>{
    {WSC_SECURITY_PROVIDER_FIREWALL, "Firewall"},
    {WSC_SECURITY_PROVIDER_ANTIVIRUS, "Antivirus"},
    {WSC_SECURITY_PROVIDER_ANTISPYWARE, "Antispyware"},
};

const auto kSecurityProviderStates = std::unordered_map<int, std::string>{
    {WSC_SECURITY_PRODUCT_STATE_ON, "On"},
    {WSC_SECURITY_PRODUCT_STATE_OFF, "Off"},
    {WSC_SECURITY_PRODUCT_STATE_SNOOZED, "Snoozed"},
    {WSC_SECURITY_PRODUCT_STATE_EXPIRED, "Expired"},
};

struct wsc_entry {
  WSC_SECURITY_PROVIDER provider;
  std::wstring product_name;
  WSC_SECURITY_PRODUCT_STATE product_state;
  std::wstring product_state_timestamp;
  std::wstring remediation_path;
  WSC_SECURITY_SIGNATURE_STATUS signature_status;
};

Status GetSecurityProducts(WSC_SECURITY_PROVIDER provider,
                           std::vector<wsc_entry>& out_list) {
  // Attempt a runtime link to the DLL containing these functions,
  // since linking the library was causing a crash on some Windows
  // machines (like the CI server).
  CLSID* productListClassPtr = nullptr;
  static HINSTANCE wscLib =
      LoadLibraryExW(L"wscapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (wscLib != nullptr) {
    productListClassPtr = (CLSID *)GetProcAddress(wscLib, "CLSID_WSCProductList");
  }

  if (productListClassPtr == nullptr) {
    return Status::failure("Could not load resources from wscapi.dll");
  }

  // Much of the following is adapted from the MS example at
  // https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/WebSecurityCenter/cpp/WscApiSample.cpp

  HRESULT hr = S_OK;
  IWscProduct* PtrProduct = nullptr;
  IWSCProductList* PtrProductList = nullptr;
  BSTR PtrVal = nullptr;
  LONG ProductCount = 0;
  WSC_SECURITY_PRODUCT_STATE ProductState;
  WSC_SECURITY_SIGNATURE_STATUS SignatureStatus;

  const auto guard =
      scope_guard::create([&PtrProduct, &PtrProductList, &PtrVal]() {
        // Be sure to clean up any lingering pointers before return
        if (nullptr != PtrVal) {
          SysFreeString(PtrVal);
        }
        if (nullptr != PtrProductList) {
          PtrProductList->Release();
        }
        if (nullptr != PtrProduct) {
          PtrProduct->Release();
        }
      });

  if (provider != WSC_SECURITY_PROVIDER_FIREWALL &&
      provider != WSC_SECURITY_PROVIDER_ANTIVIRUS &&
      provider != WSC_SECURITY_PROVIDER_ANTISPYWARE) {
    std::stringstream err_msg;
    err_msg << "Invalid security provider code: 0x" << std::hex << provider;
    VLOG(1) << err_msg.rdbuf();
    return Status::failure(err_msg.str());
  }

  // Initialize can only be called once per instance, so you need to
  // CoCreateInstance for each security product type you want to query.
  hr = CoCreateInstance((REFCLSID)(*productListClassPtr),
                        NULL,
                        CLSCTX_INPROC_SERVER,
                        __uuidof(IWSCProductList),
                        reinterpret_cast<LPVOID*>(&PtrProductList));
  if (FAILED(hr)) {
    std::stringstream err_msg;
    err_msg << "Failed to create provider instances: 0x" << std::hex << hr;
    VLOG(1) << err_msg.rdbuf();
    return Status::failure(err_msg.str());
  }

  // Initialize the product list with the type of security product you're
  // interested in.
  hr = PtrProductList->Initialize(provider);
  if (FAILED(hr)) {
    std::stringstream err_msg;
    err_msg << "Failed to initialize provider: 0x" << std::hex << hr;
    VLOG(1) << err_msg.rdbuf();
    return Status::failure(err_msg.str());
  }

  // Get the number of security products of that type.
  hr = PtrProductList->get_Count(&ProductCount);
  if (FAILED(hr)) {
    std::stringstream err_msg;
    err_msg << "Failed to get products count: 0x" << std::hex << hr;
    VLOG(1) << err_msg.rdbuf();
    return Status::failure(err_msg.str());
  }

  // Loop over each product, querying the specific attributes.
  for (LONG i = 0; i < ProductCount; i++) {
    // Get the next security product
    hr = PtrProductList->get_Item(i, &PtrProduct);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get product item: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    wsc_entry tmp;
    tmp.provider = provider;

    // Get the product name
    hr = PtrProduct->get_ProductName(&PtrVal);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get product name: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    tmp.product_name = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    // Get the product state
    hr = PtrProduct->get_ProductState(&ProductState);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get product state: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    tmp.product_state = ProductState;

    // Get the remediation path for the security product
    hr = PtrProduct->get_RemediationPath(&PtrVal);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get remediation path: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    tmp.remediation_path = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    // Get the signature status
    hr = PtrProduct->get_SignatureStatus(&SignatureStatus);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get signature status: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    tmp.signature_status = SignatureStatus;

    // Get the state timestamp
    hr = PtrProduct->get_ProductStateTimestamp(&PtrVal);
    if (FAILED(hr)) {
      std::stringstream err_msg;
      err_msg << "Failed to get product state timestamp: 0x" << std::hex << hr;
      VLOG(1) << err_msg.rdbuf();
      return Status::failure(err_msg.str());
    }
    tmp.product_state_timestamp = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    PtrProduct->Release();
    PtrProduct = nullptr;

    out_list.push_back(tmp);
  }

  return Status::success();
}

void GetAllSecurityProducts(std::vector<wsc_entry>& out_list) {
  if (!GetSecurityProducts(WSC_SECURITY_PROVIDER_FIREWALL, out_list).ok()) {
    VLOG(1) << "Failed to get firewall products";
  }
  if (!GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTIVIRUS, out_list).ok()) {
    VLOG(1) << "Failed to get antivirus products";
  }
  if (!GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTISPYWARE, out_list).ok()) {
    VLOG(1) << "Failed to get antispyware products";
  }
}

QueryData gen_wsp(QueryContext& context) {
  QueryData results;
  std::vector<wsc_entry> products;
  GetAllSecurityProducts(products);
  // Use this to convert std::wstring into std::string
  for (const auto& product : products) {
    Row r;
    r["type"] = tryTakeCopy(kSecurityProviders, product.provider)
                    .takeOr(std::string("Unknown"));
    r["name"] = wstringToString(product.product_name.c_str());
    r["state_timestamp"] =
        wstringToString(product.product_state_timestamp.c_str());
    r["remediation_path"] = wstringToString(product.remediation_path.c_str());
    r["state"] = tryTakeCopy(kSecurityProviderStates, product.product_state)
                     .takeOr(std::string("Unknown"));
    r["signatures_up_to_date"] =
        INTEGER(product.signature_status == WSC_SECURITY_PRODUCT_UP_TO_DATE);
    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
