/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>
#include <string>

#include <osquery/logger/logger.h>

#include <wbemidl.h>

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {

namespace {

/* Maximum factor between UTF16 code units and UTF8 code units.
   Surrogate pairs require 2 code units in UTF16,
   and 4 code units (bytes) in UTF8, so the factor is 2.
   Code points between U0800 to UFFFF require 1 code unit in UTF16,
   but 3 code units (bytes) in UTF8, so the factor is 3. */
static constexpr std::size_t Utf16Utf8Factor = 3;

/* NOTE: There's no factor for UTF8 -> UTF16 because the worst case
   is for ASCII, where 1 code unit in UTF8 (1 byte) becomes
   1 code unit in UTF16 (2 bytes).
   In all other cases UTF16 is actually smaller. */

/* The MultiByteToWideChar and WideCharToMultiByte functions only support
   int32_t count of characters, but C++ strings and wcslen/wcsnlen
   can potentially overflow the count. So these are the actual safe maximum
   number of characters that can be present in the input string,
   to prevent overflowing. */
static constexpr std::size_t kMaxUtf8Chars =
    std::numeric_limits<std::int32_t>::max();
static constexpr std::size_t kMaxUtf16Chars =
    std::numeric_limits<std::int32_t>::max() / Utf16Utf8Factor;

// Helper object used by Wide/Narrow converter functions

struct utf_converter {
  std::wstring from_bytes(const std::string& str) {
    std::wstring result;

    if (!str.empty() && str.length() <= kMaxUtf8Chars) {
      std::int32_t utf16_chars = static_cast<std::int32_t>(str.length());
      std::int32_t utf8_chars = static_cast<std::int32_t>(str.length());

      result.resize(utf16_chars);
      auto count = MultiByteToWideChar(
          CP_UTF8, 0, str.c_str(), utf8_chars, &result[0], utf16_chars);
      result.resize(count);
    }

    return result;
  }

  std::string to_bytes(const std::wstring& str) {
    std::string result;

    if (str.length() > 0 && str.length() <= kMaxUtf16Chars) {
      std::int32_t utf8_chars =
          static_cast<std::int32_t>(str.length() * Utf16Utf8Factor);

      std::int32_t utf16_chars = static_cast<std::int32_t>(str.length());

      result.resize(utf8_chars);
      auto count = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       str.c_str(),
                                       utf16_chars,
                                       &result[0],
                                       utf8_chars,
                                       nullptr,
                                       nullptr);
      result.resize(count);
    }

    return result;
  }

  std::string to_bytes(const wchar_t* str, std::int32_t size) {
    std::string result;
    std::int32_t utf8_chars = size * Utf16Utf8Factor;

    result.resize(utf8_chars);
    auto count = WideCharToMultiByte(
        CP_UTF8, 0, str, size, &result[0], utf8_chars, nullptr, nullptr);
    result.resize(count);

    return result;
  }
};

static utf_converter converter;

} // namespace

std::wstring stringToWstring(const char* src) {
  std::wstring utf16le_str;

  std::size_t size = strlen(src);

  if (size == 0 || size > kMaxUtf8Chars) {
    return {};
  }

  utf16le_str = converter.from_bytes(src);

  return utf16le_str;
}

std::wstring stringToWstring(const std::string& src) {
  std::wstring utf16le_str;
  utf16le_str = converter.from_bytes(src);

  return utf16le_str;
}

std::string wstringToString(const std::wstring& src) {
  return converter.to_bytes(src);
}

std::string wstringToString(const wchar_t* src, std::size_t max_chars) {
  if (src == nullptr || max_chars == 0) {
    return {};
  }

  std::size_t size = wcsnlen(src, max_chars);

  if (size == 0 || size > kMaxUtf16Chars) {
    return {};
  }

  return converter.to_bytes(src, static_cast<std::int32_t>(size));
}

std::string wstringToString(const wchar_t* src) {
  if (src == nullptr) {
    return {};
  }

  std::size_t size = wcslen(src);

  if (size == 0 || size > kMaxUtf16Chars) {
    return {};
  }

  return converter.to_bytes(src, static_cast<std::int32_t>(size));
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
  auto bSrcStr = SysAllocString(stringToWstring(src).c_str());
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
