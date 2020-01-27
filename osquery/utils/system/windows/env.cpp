/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/env.h>

#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <windows.h>

namespace osquery {

bool setEnvVar(const std::string& name, const std::string& value) {
  const std::wstring widename = stringToWstring(name);
  const std::wstring widevalue = stringToWstring(value);

  return ::SetEnvironmentVariableW(widename.c_str(), widevalue.c_str()) == TRUE;
}

bool unsetEnvVar(const std::string& name) {
  const std::wstring widename = stringToWstring(name);
  return ::SetEnvironmentVariableW(widename.c_str(), nullptr) == TRUE;
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  const auto kInitialBufferSize = 1024;
  std::vector<WCHAR> buf;
  buf.assign(kInitialBufferSize, L'\0');

  const std::wstring widename = stringToWstring(name);

  auto value_len = ::GetEnvironmentVariableW(
      widename.c_str(), buf.data(), kInitialBufferSize);
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
        ::GetEnvironmentVariableW(widename.c_str(), buf.data(), value_len);
  }

  if (value_len == 0 || value_len > buf.size()) {
    // The size returned is greater than the size we expected. Currently, we
    // will not deal with this scenario and just return as if an error has
    // occurred.
    return boost::none;
  }

  return wstringToString(buf.data());

} // namespace osquery

} // namespace osquery
