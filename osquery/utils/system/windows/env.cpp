/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/env.h>
#include <osquery/utils/system/errno.h>

#include <string>
#include <vector>

#include <boost/optional.hpp>

// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on

namespace osquery {

const auto kInitialBufferSize = 1024;

// NOTE: ExpandEnvironmentStrings doesn't support inputs larger than 32k.
// The MSDN documentation refers to this limit as the size of the buffer, so
// we assume that the null terminator is counted and subtract it here.
const auto kEnvironmentExpansionMax = 32767;

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
}

boost::optional<std::string> expandEnvString(const std::string& input) {
  std::vector<WCHAR> buf;
  buf.assign(kInitialBufferSize, L'\0');

  if (input.size() > kEnvironmentExpansionMax) {
    VLOG(1) << "Not expanding environment string larger than "
            << kEnvironmentExpansionMax << " bytes";
    return boost::none;
  }

  std::wstring const winput = stringToWstring(input);

  auto len = ::ExpandEnvironmentStrings(
      winput.c_str(), buf.data(), kInitialBufferSize);
  if (len == 0) {
    std::wstring description;
    if (!getWindowsErrorDescription(description, ::GetLastError())) {
      description = L"Unknown error";
    }
    VLOG(1) << "Failed to expand environment string: "
            << wstringToString(description);

    return boost::none;
  }

  if (len > kInitialBufferSize) {
    buf.assign(len, '\0');
    len = ::ExpandEnvironmentStrings(winput.c_str(), buf.data(), len);
  }

  if (len == 0) {
    std::wstring description;
    if (!getWindowsErrorDescription(description, ::GetLastError())) {
      description = L"Unknown error";
    }
    VLOG(1) << "Failed to expand environment string: "
            << wstringToString(description);

    return boost::none;
  }

  // Unlike GetEnvironmentVariableA, the length returned by
  // ExpandEnvironmentStrings does include the terminating null.
  return wstringToString(std::wstring(buf.data(), len - 1));
}

boost::optional<std::vector<std::string>> splitArgs(const std::string& args) {
  int argc = 0;

  // If the string is empty, there is nothing to split.
  if (args.empty()) {
    return boost::none;
  }

  // Note: passing an empty string to CommandLineToArgvW() will cause it
  // to fill in the command line of the current process (of osquery!)
  auto argv = ::CommandLineToArgvW(stringToWstring(args).c_str(), &argc);
  if (argv == nullptr) {
    return boost::none;
  }

  std::vector<std::string> argvec;
  for (int i = 0; i < argc; ++i) {
    argvec.push_back(wstringToString(argv[i]));
  }

  LocalFree(argv);

  return argvec;
}

} // namespace osquery
