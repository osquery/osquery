#include <codecvt>
#include <locale>

#include <iwscapi.h>
#include <wscapi.h>

#include <osquery/core.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

typedef struct wsc_entry {
  WSC_SECURITY_PROVIDER provider;
  std::wstring product_name;
  WSC_SECURITY_PRODUCT_STATE product_state;
  std::wstring product_state_timestamp;
  std::wstring remediation_path;
  WSC_SECURITY_SIGNATURE_STATUS signature_status;
} wsc_entry;

HRESULT GetSecurityProducts(WSC_SECURITY_PROVIDER provider,
                            std::list<wsc_entry>& out_list) {
  // Much of the following is adapted from the MS example at
  // https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/WebSecurityCenter/cpp/WscApiSample.cpp

  HRESULT hr = S_OK;
  IWscProduct* PtrProduct = nullptr;
  IWSCProductList* PtrProductList = nullptr;
  BSTR PtrVal = nullptr;
  LONG ProductCount = 0;
  WSC_SECURITY_PRODUCT_STATE ProductState;
  WSC_SECURITY_SIGNATURE_STATUS SignatureStatus;

  if (provider != WSC_SECURITY_PROVIDER_FIREWALL &&
      provider != WSC_SECURITY_PROVIDER_ANTIVIRUS &&
      provider != WSC_SECURITY_PROVIDER_ANTISPYWARE) {
    VLOG(1) << "Invalid security provider code: " << provider;
    hr = E_INVALIDARG;
    goto exit;
  }

  // Initialize can only be called once per instance, so you need to
  // CoCreateInstance for each security product type you want to query.
  hr = CoCreateInstance(CLSID_WSCProductList,
                        NULL,
                        CLSCTX_INPROC_SERVER,
                        __uuidof(IWSCProductList),
                        reinterpret_cast<LPVOID*>(&PtrProductList));
  if (FAILED(hr)) {
    VLOG(1) << "Failed to create provider instances: " << hr;
    goto exit;
  }

  // Initialize the product list with the type of security product you're
  // interested in.
  hr = PtrProductList->Initialize(provider);
  if (FAILED(hr)) {
    VLOG(1) << "Failed to initialize provider: " << hr;
    goto exit;
  }

  // Get the number of security products of that type.
  hr = PtrProductList->get_Count(&ProductCount);
  if (FAILED(hr)) {
    VLOG(1) << "Failed to get products count: " << hr;
    goto exit;
  }

  // Loop over each product, querying the specific attributes.
  for (LONG i = 0; i < ProductCount; i++) {
    // Get the next security product
    hr = PtrProductList->get_Item(i, &PtrProduct);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get product item: " << hr;
      goto exit;
    }
    wsc_entry tmp;
    tmp.provider = provider;

    // Get the product name
    hr = PtrProduct->get_ProductName(&PtrVal);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get product name: " << hr;
      goto exit;
    }
    tmp.product_name = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    // Get the product state
    hr = PtrProduct->get_ProductState(&ProductState);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get product state: " << hr;
      goto exit;
    }
    tmp.product_state = ProductState;

    // Get the remediation path for the security product
    hr = PtrProduct->get_RemediationPath(&PtrVal);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get remediation path: " << hr;
      goto exit;
    }
    tmp.remediation_path = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    // Get the signature status
    hr = PtrProduct->get_SignatureStatus(&SignatureStatus);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get signature status: " << hr;
      goto exit;
    }
    tmp.signature_status = SignatureStatus;

    // Get the state timestamp
    hr = PtrProduct->get_ProductStateTimestamp(&PtrVal);
    if (FAILED(hr)) {
      VLOG(1) << "Failed to get product state timestamp: " << hr;
      goto exit;
    }
    tmp.product_state_timestamp = PtrVal;
    SysFreeString(PtrVal);
    PtrVal = nullptr;

    PtrProduct->Release();
    PtrProduct = nullptr;

    out_list.push_back(tmp);
  }

exit:
  if (nullptr != PtrVal) {
    SysFreeString(PtrVal);
  }
  if (nullptr != PtrProductList) {
    PtrProductList->Release();
  }
  if (nullptr != PtrProduct) {
    PtrProduct->Release();
  }
  return hr;
}

void GetAllSecurityProducts(std::list<wsc_entry>& out_list) {
  if (FAILED(GetSecurityProducts(WSC_SECURITY_PROVIDER_FIREWALL, out_list))) {
    VLOG(1) << "Failed to get firewall products";
  }
  if (FAILED(GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTIVIRUS, out_list))) {
    VLOG(1) << "Failed to get antivirus products";
  }
  if (FAILED(
          GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTISPYWARE, out_list))) {
    VLOG(1) << "Failed to get antispyware products";
  }
}

namespace osquery {
namespace tables {

QueryData gen_wsp(QueryContext& context) {
  QueryData results;
  std::list<wsc_entry> products;
  GetAllSecurityProducts(products);
  // Use this to convert std::wstring into std::string
  auto& str_converter = std::wstring_convert<std::codecvt_utf8<wchar_t>>();
  for (const auto& product : products) {
    Row r;

    switch (product.provider) {
    case WSC_SECURITY_PROVIDER_FIREWALL:
      r["type"] = "Firewall";
      break;
    case WSC_SECURITY_PROVIDER_ANTIVIRUS:
      r["type"] = "Antivirus";
      break;
    case WSC_SECURITY_PROVIDER_ANTISPYWARE:
      r["type"] = "Antispyware";
      break;
    default:
      r["type"] = "Unknown";
      break;
    }

    r["name"] = str_converter.to_bytes(product.product_name);
    r["state_timestamp"] =
        str_converter.to_bytes(product.product_state_timestamp);
    r["remediation_path"] = str_converter.to_bytes(product.remediation_path);

    switch (product.product_state) {
    case WSC_SECURITY_PRODUCT_STATE_ON:
      r["state"] = "On";
      break;
    case WSC_SECURITY_PRODUCT_STATE_OFF:
      r["state"] = "Off";
      break;
    case WSC_SECURITY_PRODUCT_STATE_SNOOZED:
      r["state"] = "Snoozed";
      break;
    case WSC_SECURITY_PRODUCT_STATE_EXPIRED:
      r["state"] = "Expired";
      break;
    default:
      r["state"] = "Unknown";
      break;
    }

    if (product.signature_status == WSC_SECURITY_PRODUCT_UP_TO_DATE) {
      r["signatures_up_to_date"] = INTEGER(1);
    } else {
      r["signatures_up_to_date"] = INTEGER(0);
    }

    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
