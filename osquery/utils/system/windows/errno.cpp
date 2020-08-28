/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/errno.h>

#include <string.h>
#include <vector>

#define MAX_BUFFER_SIZE 256

namespace osquery {
const auto kWindowsLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

std::string platformStrerr(int errnum) {
  std::vector<char> buffer;
  buffer.assign(MAX_BUFFER_SIZE, '\0');

  auto status = ::strerror_s(buffer.data(), buffer.size(), errnum);
  if (status != 0) {
    return "";
  }

  return std::string(buffer.data());
}

Status getWindowsErrorDescription(std::wstring& error_message, DWORD error_id) {
  error_message.clear();
  LPWSTR buffer = nullptr;

  auto message_size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                         FORMAT_MESSAGE_FROM_SYSTEM |
                                         FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr,
                                     error_id,
                                     kWindowsLanguageId,
                                     reinterpret_cast<LPWSTR>(&buffer),
                                     0,
                                     nullptr);

  if (message_size == 0U) {
    return Status(1,
                  "Failed to fetch the Windows error message for the following "
                  "error code: " +
                      std::to_string(error_id));
  }

  error_message = buffer;
  LocalFree(buffer);

  return Status(0);
}

} // namespace osquery
