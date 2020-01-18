/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <codecvt>
#include <string>

#include <osquery/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

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

} // namespace osquery
