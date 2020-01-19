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

bool setEnvVar(const std::wstring& name, const std::wstring& value) {
  return (::SetEnvironmentVariableW(name.c_str(), value.c_str()) == TRUE);
}

bool unsetEnvVar(const std::wstring& name) {
  return (::SetEnvironmentVariableW(name.c_str(), nullptr) == TRUE);
}

boost::optional<std::wstring> getEnvVar(const std::wstring& name) {
  const auto kInitialBufferSize = 1024;
  std::vector<WCHAR> buf;
  buf.assign(kInitialBufferSize, '\0');

  auto value_len =
      ::GetEnvironmentVariableW(name.c_str(), buf.data(), kInitialBufferSize);
  if (value_len == 0) {
    return boost::none;
  }

  // It is always possible that between the first GetEnvironmentVariableA call
  // and this one, a change was made to our target environment variable that
  // altered the size. Currently, we ignore this scenario and fail if the
  // returned size is greater than what we expect.
  if (value_len > kInitialBufferSize) {
    buf.assign(value_len, '\0');
    value_len = ::GetEnvironmentVariableW(name.c_str(), buf.data(), value_len);
    if (value_len == 0 || value_len > buf.size()) {
      // The size returned is greater than the size we expected. Currently, we
      // will not deal with this scenario and just return as if an error has
      // occurred.
      return boost::none;
    }
  }

  return std::wstring(buf.data(), value_len);
}

} // namespace osquery
