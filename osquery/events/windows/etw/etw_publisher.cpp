/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/windows/etw/etw_publisher.h>

#include <osquery/utils/scope_guard.h>

namespace osquery {

EtwPublisherBase::EtwPublisherBase(const std::string& name) {
  name_ = name;
  initializeHardVolumeConversions();
}

EtwController& EtwPublisherBase::EtwEngine() {
  return etwController_;
}

Status EtwPublisherBase::run() {
  return Status::failure(0,
                         "ETW provider is driven by event callbacks. "
                         "A pooling thread is not required.");
}

std::function<void(const EtwEventDataRef&)>
EtwPublisherBase::getPostProcessorCallback() {
  return [this](const EtwEventDataRef& data) {
    this->providerPostProcessor(data);
  };
}

void EtwPublisherBase::updateUserInfo(const std::string& userSid,
                                      std::string& username) {
  // Updating user information using gathered user SIDs as input
  auto usernameIt = usernamesBySIDs_.find(userSid);
  if (usernameIt != usernamesBySIDs_.end()) {
    auto cachedUsername = usernameIt->second;
    username.assign(cachedUsername);
  } else {
    PSID pSid = nullptr;

    std::wstring userSidW = stringToWstring(userSid);
    if (!ConvertStringSidToSidW(userSidW.c_str(), &pSid) || pSid == nullptr) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      return;
    }
    auto sid_guard = scope_guard::create([&pSid]() { LocalFree(pSid); });

    std::vector<wchar_t> domainNameStr(MAX_PATH, 0x0);
    std::vector<wchar_t> userNameStr(MAX_PATH, 0x0);
    DWORD domainNameSize = MAX_PATH;
    DWORD userNameSize = MAX_PATH;
    SID_NAME_USE sidType = SID_NAME_USE::SidTypeInvalid;

    if (!LookupAccountSidW(NULL,
                           pSid,
                           userNameStr.data(),
                           &userNameSize,
                           domainNameStr.data(),
                           &domainNameSize,
                           &sidType) ||
        wcsnlen_s(domainNameStr.data(), MAX_PATH) == 0 ||
        wcsnlen_s(domainNameStr.data(), MAX_PATH) >= MAX_PATH ||
        wcsnlen_s(userNameStr.data(), MAX_PATH) == 0 ||
        wcsnlen_s(userNameStr.data(), MAX_PATH) >= MAX_PATH ||
        sidType == SID_NAME_USE::SidTypeInvalid) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      return;
    }

    std::wstring usernameW;
    usernameW.append(domainNameStr.data());
    usernameW.append(L"\\");
    usernameW.append(userNameStr.data());

    username = wstringToString(usernameW);

    usernamesBySIDs_.insert({userSid, username});
  }
}

void EtwPublisherBase::initializeHardVolumeConversions() {
  const auto& validDriveLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for (const auto& driveLetter : validDriveLetters) {
    // Convert drive letter to a wide-character string
    std::string queryPath;
    queryPath.push_back(driveLetter);
    queryPath.push_back(':');
    std::wstring queryPathW = stringToWstring(queryPath);

    wchar_t hardVolumeW[MAX_PATH + 1] = {0};
    if (QueryDosDeviceW(queryPathW.c_str(), hardVolumeW, MAX_PATH)) {
      // Convert wide-character strings back to UTF-8 for storage
      std::string hardVolume = wstringToString(hardVolumeW);
      hardVolumeDrives_.insert({hardVolume, queryPath});
    }
  }
}

void EtwPublisherBase::updateHardVolumeWithLogicalDrive(std::string& path) {
  // Updating the hardvolume entries with logical volume data
  for (const auto& [hardVolume, logicalDrive] : hardVolumeDrives_) {
    size_t pos = 0;
    if ((pos = path.find(hardVolume, pos)) != std::string::npos) {
      path.replace(pos, hardVolume.length(), logicalDrive);
      break;
    }
  }
}

} // namespace osquery
