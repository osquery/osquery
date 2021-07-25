/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <codecvt>
#include <string>

#include <osquery/logger/logger.h>

#include <wbemidl.h>

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {

// Helper object used by Wide/Narrow converter functions

struct utf_converter {
  std::wstring from_bytes(const std::string& str) {
    std::wstring result;
    if (str.length() > 0) {
      result.resize(str.length() * 2);
      auto count = MultiByteToWideChar(
          CP_UTF8, 0, str.c_str(), -1, &result[0], str.length() * 2);
      result.resize(count - 1);
    }

    return result;
  }

  std::string to_bytes(const std::wstring& str) {
    std::string result;
    if (str.length() > 0) {
      result.resize(str.length() * 4);
      auto count = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       str.c_str(),
                                       -1,
                                       &result[0],
                                       str.length() * 4,
                                       NULL,
                                       NULL);
      result.resize(count - 1);
    }

    return result;
  }
};

static utf_converter converter;

std::wstring stringToWstring(const std::string& src) {
  std::wstring utf16le_str;
  try {
    utf16le_str = converter.from_bytes(src);
  } catch (std::exception /* e */) {
    LOG(WARNING) << "Failed to convert string to wstring " << src;
  }

  return utf16le_str;
}

std::string wstringToString(const std::wstring& src) {
  std::string utf8_str = converter.to_bytes(src);
  return utf8_str;
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

LONGLONG cimDatetimeToUnixtime(const std::string& src) {
  // First init the SWbemDateTime class
  ISWbemDateTime* pCimDateTime = nullptr;
  auto hres = CoCreateInstance(CLSID_SWbemDateTime,
                               nullptr,
                               CLSCTX_INPROC_SERVER,
                               IID_PPV_ARGS(&pCimDateTime));
  if (!SUCCEEDED(hres)) {
    LOG(WARNING) << "Failed to init CoCreateInstance with " << hres;
    return -1;
  }
  auto pCimDateTimeManager = scope_guard::create([&pCimDateTime]() {
    if (pCimDateTime != nullptr) {
      pCimDateTime->Release();
    }
  });

  // Then load up our CIM Datetime string into said class
  auto bSrcStr = SysAllocString(stringToWstring(src.c_str()).c_str());
  auto const bSrcStrManager =
      scope_guard::create([&bSrcStr]() { SysFreeString(bSrcStr); });
  hres = pCimDateTime->put_Value(bSrcStr);
  if (!SUCCEEDED(hres)) {
    LOG(WARNING) << "Failed to init CimDateTime with " << hres;
    return -1;
  }

  // Convert this CIM Datetime to a FILETIME BSTR
  BSTR bstrFileTime{L""};
  auto const bstrFileTimeManager =
      scope_guard::create([&bstrFileTime]() { SysFreeString(bstrFileTime); });
  // VARIANT_FALSE means we fetch the time in UTC
  hres = pCimDateTime->GetFileTime(VARIANT_FALSE, &bstrFileTime);
  if (!SUCCEEDED(hres)) {
    LOG(WARNING) << "Failed to convert CimDateTime to FILETIME with " << hres;
    return -1;
  }

  LARGE_INTEGER intStore;
  intStore.QuadPart = _wtoi64(bstrFileTime);
  FILETIME timeStore;

  timeStore.dwLowDateTime = intStore.LowPart;
  timeStore.dwHighDateTime = intStore.HighPart;

  // And finally convert this to a Unix epoch timestamp
  return filetimeToUnixtime(timeStore);
}

std::string swapEndianess(const std::string& endian_string) {
  std::string swap_string = endian_string;
  std::reverse(swap_string.begin(), swap_string.end());
  for (std::size_t i = 0; i < swap_string.length(); i += 2) {
    std::swap(swap_string[i], swap_string[i + 1]);
  }
  return swap_string;
}

std::string errorDwordToString(DWORD error_code) {
  LPWSTR msg_buffer = nullptr;

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL,
                 error_code,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPWSTR)&msg_buffer,
                 0,
                 NULL);

  if (msg_buffer != NULL) {
    auto error_message = wstringToString(msg_buffer);
    LocalFree(msg_buffer);
    msg_buffer = nullptr;

    return error_message;
  }

  VLOG(1) << "FormatMessage failed for code (" << std::to_string(error_code)
          << ")";
  return std::string("Error code " + std::to_string(error_code) + " not found");
}

} // namespace osquery
