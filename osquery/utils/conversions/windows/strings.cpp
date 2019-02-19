/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <codecvt>
#include <string>

#include <glog/logging.h>

#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

// Helper object used by Wide/Narrow converter functions
static std::wstring_convert<
    std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::little_endian>>
    converter;

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
