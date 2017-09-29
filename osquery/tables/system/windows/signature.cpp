/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <codecvt>
#include <map>
#include <string>

// clang-format off
#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <Softpub.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
// This is defined in osquery/core/windows/wmi.cpp
std::wstring stringToWstring(const std::string& src);

struct SignatureInformation final {
  enum class Result { Valid, Trusted, Invalid, Missing, Distrusted, Untrusted };

  std::string path;
  Result result;
};

void generateRow(Row& row, const SignatureInformation& signature_info) {
  row.clear();

  row["path"] = signature_info.path;

  switch (signature_info.result) {
  case SignatureInformation::Result::Valid: {
    row["result"] = "valid";
    break;
  }

  case SignatureInformation::Result::Trusted: {
    row["result"] = "trusted";
    break;
  }

  case SignatureInformation::Result::Invalid: {
    row["result"] = "invalid";
    break;
  }

  case SignatureInformation::Result::Missing: {
    row["result"] = "missing";
    break;
  }

  case SignatureInformation::Result::Distrusted: {
    row["result"] = "distrusted";
    break;
  }

  case SignatureInformation::Result::Untrusted: {
    row["result"] = "untrusted";
    break;
  }

  default: {
    row["result"] = "unknown";
    LOG(ERROR) << "Unexpected result value";
    break;
  }
  }
}

Status querySignatureInformation(SignatureInformation& signature_info,
                                 const std::string& path) {
  std::wstring utf16_path = stringToWstring(path);
  if (utf16_path.empty()) {
    return Status(1, "Invalid path");
  }

  signature_info.path = path;

  WINTRUST_DATA trust_provider_settings = {};
  trust_provider_settings.cbStruct = sizeof(WINTRUST_DATA);

  // Set the input file
  WINTRUST_FILE_INFO file_info = {};
  file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
  file_info.pcwszFilePath = utf16_path.data();
  trust_provider_settings.pFile = &file_info;

  // Do revocation checking
  trust_provider_settings.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;

  // Disable the UI
  trust_provider_settings.dwUIChoice = WTD_UI_NONE;

  // Verify an embedded signature
  trust_provider_settings.dwStateAction = WTD_STATEACTION_VERIFY;
  trust_provider_settings.dwUnionChoice = WTD_CHOICE_FILE;

  // Do the actual verification
  GUID authenticode_policy_provider = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  Status exit_status;

  auto verification_status =
      WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                     &authenticode_policy_provider,
                     &trust_provider_settings);

  switch (verification_status) {
  // Signatures that have been distrusted by the administrator
  case TRUST_E_EXPLICIT_DISTRUST: {
    signature_info.result = SignatureInformation::Result::Distrusted;
    exit_status = Status(0, "Ok");
    break;
  }

  // There may be no signature, but we also end up here if the file is malformed
  // or not accessible.
  case TRUST_E_NOSIGNATURE: {
    auto error_code = GetLastError();
    if (error_code == TRUST_E_NOSIGNATURE ||
        error_code == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        error_code == TRUST_E_PROVIDER_UNKNOWN) {
      signature_info.result = SignatureInformation::Result::Missing;
      exit_status = Status(0, "Ok");
    } else {
      exit_status =
          Status(1, std::string("Failed to verify the file signature") + path);
    }

    break;
  }

  case ERROR_SUCCESS: {
    signature_info.result = SignatureInformation::Result::Trusted;
    exit_status = Status(0, "Ok");
    break;
  }

  // Although this signature is perfectly valid, it wasn't explicitly trusted
  // by the system administrator
  case CRYPT_E_SECURITY_SETTINGS: {
    signature_info.result = SignatureInformation::Result::Valid;
    exit_status = Status(0, "Ok");
    break;
  }

  case TRUST_E_SUBJECT_NOT_TRUSTED:
  default: {
    signature_info.result = SignatureInformation::Result::Untrusted;
    exit_status = Status(0, "Ok");
    break;
  }
  }

  trust_provider_settings.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                 &authenticode_policy_provider,
                 &trust_provider_settings);

  return exit_status;
}

namespace tables {
Status generateRow(Row& r, const std::string& path) {
  r = {};

  SignatureInformation signature_info;
  auto status = querySignatureInformation(signature_info, path);
  if (!status.ok()) {
    std::stringstream error_message;
    error_message << "Failed to verify the Authenticode signature for the "
                     "following file: "
                  << path << ". Error: " << status.getMessage();

    return Status(1, error_message.str());
  }

  generateRow(r, signature_info);
  return Status(0, "Ok");
}

QueryData generateQueryResults(QueryContext& context) {
  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  QueryData results;
  for (const auto& path_string : paths) {
    Row r;
    auto status = generateRow(r, path_string);
    if (status.ok()) {
      results.push_back(r);
    } else {
      LOG(WARNING) << status.getMessage();
    }
  }

  return results;
}
}
}
