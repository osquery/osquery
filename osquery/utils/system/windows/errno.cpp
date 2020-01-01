/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

Status getWindowsErrorDescription(std::string& error_message, DWORD error_id) {
  error_message.clear();
  LPSTR buffer = nullptr;

  auto message_size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                         FORMAT_MESSAGE_FROM_SYSTEM |
                                         FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr,
                                     error_id,
                                     kWindowsLanguageId,
                                     reinterpret_cast<LPSTR>(&buffer),
                                     0,
                                     nullptr);

  if (message_size == 0U) {
    return Status(1,
                  "Failed to fetch the Windows error message for the following "
                  "error code: " +
                      std::to_string(error_id));
  }

  error_message.assign(buffer, static_cast<size_t>(message_size));
  LocalFree(buffer);

  return Status(0);
}

} // namespace osquery
