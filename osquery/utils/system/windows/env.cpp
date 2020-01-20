/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/env.h>

#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <windows.h>

namespace osquery {

bool setEnvVar(const std::string& name, const std::string& value) {
  bool status = false;
  std::vector<WCHAR> widename;
  widename.assign((name.length() + 1) * 2, '\0');

  std::vector<WCHAR> widevalue;
  widevalue.assign((value.length() + 1) * 2, '\0');

  if (0 != MultiByteToWideChar(CP_UTF8,
                               0,
                               name.c_str(),
                               -1,
                               widename.data(),
                               (name.length() + 1) * 2)) {
    if (0 != MultiByteToWideChar(CP_UTF8,
                                 0,
                                 value.c_str(),
                                 -1,
                                 widevalue.data(),
                                 (value.length() + 1) * 2)) {
      status = (::SetEnvironmentVariableW(widename.data(), widevalue.data()) ==
                TRUE);
    }
  }

  return status;
}

bool unsetEnvVar(const std::string& name) {
  bool status = false;
  std::vector<WCHAR> widename;
  widename.assign((name.length() + 1) * 2, '\0');

  if (0 != MultiByteToWideChar(CP_UTF8,
                               0,
                               name.c_str(),
                               -1,
                               widename.data(),
                               (name.length() + 1) * 2)) {
    status = (::SetEnvironmentVariableW(widename.data(), nullptr) == TRUE);
  }

  return status;
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  const auto kInitialBufferSize = 1024;
  std::vector<WCHAR> buf;
  buf.assign(kInitialBufferSize, '\0');

  std::vector<WCHAR> widename;
  widename.assign((name.length() + 1) * 2, '\0');

  std::vector<CHAR> narrowvalue;

  if (0 != MultiByteToWideChar(CP_UTF8,
                               0,
                               name.c_str(),
                               -1,
                               widename.data(),
                               (name.length() + 1) * 2)) {
    auto value_len = ::GetEnvironmentVariableW(
        widename.data(), buf.data(), kInitialBufferSize);
    if (value_len == 0) {
      return boost::none;
    }

    // It is always possible that between the first GetEnvironmentVariableA call
    // and this one, a change was made to our target environment variable that
    // altered the size. Currently, we ignore this scenario and fail if the
    // returned size is greater than what we expect.
    if (value_len > kInitialBufferSize) {
      buf.assign(value_len, '\0');
      value_len =
          ::GetEnvironmentVariableW(widename.data(), buf.data(), value_len);
      if (value_len == 0 || value_len > buf.size()) {
        // The size returned is greater than the size we expected. Currently, we
        // will not deal with this scenario and just return as if an error has
        // occurred.
        return boost::none;
      }
    }

    narrowvalue.assign((value_len + 1) * 4, '\0');
    WideCharToMultiByte(CP_UTF8,
                        0,
                        buf.data(),
                        -1,
                        narrowvalue.data(),
                        (value_len + 1) * 4,
                        0,
                        nullptr);

    return narrowvalue.data();
  }

  return std::string();
}

} // namespace osquery
