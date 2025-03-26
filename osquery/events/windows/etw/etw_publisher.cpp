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

    if (!ConvertStringSidToSidA(userSid.c_str(), &pSid) || pSid == nullptr) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      return;
    }

    std::vector<char> domainNameStr(MAX_PATH - 1, 0x0);
    std::vector<char> userNameStr(MAX_PATH - 1, 0x0);
    DWORD domainNameSize = MAX_PATH;
    DWORD userNameSize = MAX_PATH;
    SID_NAME_USE sidType = SID_NAME_USE::SidTypeInvalid;

    if (!LookupAccountSidA(NULL,
                           pSid,
                           userNameStr.data(),
                           &userNameSize,
                           domainNameStr.data(),
                           &domainNameSize,
                           &sidType) ||
        strlen(domainNameStr.data()) == 0 ||
        strlen(domainNameStr.data()) >= MAX_PATH ||
        strlen(userNameStr.data()) == 0 ||
        strlen(userNameStr.data()) >= MAX_PATH ||
        sidType == SID_NAME_USE::SidTypeInvalid) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      LocalFree(pSid);
      return;
    }

    LocalFree(pSid);

    username.append(domainNameStr.data());
    username.append("\\");
    username.append(userNameStr.data());

    usernamesBySIDs_.insert({userSid, username});
  }
}

void EtwPublisherBase::initializeHardVolumeConversions() {
  const auto& validDriveLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for (const auto& driveLetter : validDriveLetters) {
    std::string queryPath;
    queryPath.push_back(driveLetter);
    queryPath.push_back(':');

    char hardVolume[MAX_PATH + 1] = {0};
    if (QueryDosDeviceA(queryPath.c_str(), hardVolume, MAX_PATH)) {
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
