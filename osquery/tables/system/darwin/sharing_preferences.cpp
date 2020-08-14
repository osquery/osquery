/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <cups/adminutil.h>
#include <cups/cups.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#ifndef __SERVICEMANAGEMENT_PRIVATE_H__
#define __SERVICEMANAGEMENT_PRIVATE_H__

#include <ServiceManagement/ServiceManagement.h>
extern "C" {
int SMJobIsEnabled(CFStringRef domain, CFStringRef service, Boolean* value);
}

#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kInternetSharingPath =
    "/Library/Preferences/SystemConfiguration/com.apple.nat.plist";

const std::string kRemoteAppleManagementPath =
    "/Library/Application Support/Apple/Remote "
    "Desktop/RemoteManagement.launchd";

const std::string kRemoteBluetoothSharingPath = "/Library/Preferences/ByHost/";

const std::string kRemoteBluetoothSharingPattern = "com.apple.Bluetooth.%";

const std::string kContentCachingPath =
    "/Library/Preferences/com.apple.AssetCache.plist";

bool remoteAppleManagementPlistExists() {
  auto remoteAppleManagementFileInfo =
      SQL::selectAllFrom("file", "path", EQUALS, kRemoteAppleManagementPath);
  if (remoteAppleManagementFileInfo.empty()) {
    return false;
  }
  return true;
}

int getScreenSharingStatus() {
  Boolean persistence = false;
  if (remoteAppleManagementPlistExists()) {
    return 0;
  }
  return SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.screensharing"), &persistence);
}

int getRemoteManagementStatus() {
  return remoteAppleManagementPlistExists() ? 1 : 0;
}

int getFileSharingStatus() {
  Boolean fileServerStatus, fileServerPersistence = false;
  Boolean smbStatus, smbPersistence = false;

  smbStatus = SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.smbd"), &smbPersistence);
  fileServerStatus = SMJobIsEnabled(kSMDomainSystemLaunchd,
                                    CFSTR("com.apple.AppleFileServer"),
                                    &fileServerPersistence);
  return smbStatus | fileServerStatus;
}

int getRemoteLoginStatus() {
  Boolean persistence = false;
  return SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.openssh.sshd"), &persistence);
}

int getRemoteAppleEventStatus() {
  Boolean persistence = false;
  return SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.AEServer"), &persistence);
}

int getDiscSharingStatus() {
  Boolean persistence = false;
  return SMJobIsEnabled(
      kSMDomainSystemLaunchd, CFSTR("com.apple.ODSAgent"), &persistence);
}

int getPrinterSharingStatus() {
  http_t* cups = nullptr;
  int num_settings = 0;
  cups_option_t* settings = nullptr;
  const char* value = nullptr;

  cups = httpConnect2(cupsServer(),
                      ippPort(),
                      nullptr,
                      AF_INET,
                      cupsEncryption(),
                      1,
                      30000,
                      nullptr);
  if (cups == nullptr) {
    return 0;
  }
  int ret = cupsAdminGetServerSettings(cups, &num_settings, &settings);
  if (ret != 0) {
    value = cupsGetOption("_share_printers", num_settings, settings);
    cupsFreeOptions(num_settings, settings);
  } else {
    VLOG(1) << "Unable to get CUPS server settings: " << cupsLastErrorString();
  }
  httpClose(cups);

  if (value != nullptr) {
    return *value == '1' ? 1 : 0;
  }
  return 0;
}

int getInterNetSharingStatus() {
  auto internetSharingStatus =
      SQL::selectAllFrom("plist", "path", EQUALS, kInternetSharingPath);
  if (internetSharingStatus.empty()) {
    return 0;
  }
  for (const auto& row : internetSharingStatus) {
    if (row.find("key") == row.end() || row.find("subkey") == row.end() ||
        row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "NAT" && row.at("subkey") == "Enabled" &&
        row.at("value") == INTEGER(1)) {
      return 1;
    }
  }
  return 0;
}

int getBluetoothSharingStatus() {
  auto users = SQL::selectAllFrom("users");
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      auto dir = fs::path(row.at("directory")) / kRemoteBluetoothSharingPath;
      if (!pathExists(dir).ok()) {
        continue;
      }
      std::vector<std::string> paths;
      if (!resolveFilePattern(dir / kRemoteBluetoothSharingPattern, paths)
               .ok()) {
        continue;
      }

      for (const auto& bluetoothSharing_path : paths) {
        auto bluetoothSharingStatus =
            SQL::selectAllFrom("plist", "path", EQUALS, bluetoothSharing_path);
        if (bluetoothSharingStatus.empty()) {
          continue;
        }
        for (const auto& r : bluetoothSharingStatus) {
          if (r.find("key") == row.end() || row.find("value") == r.end()) {
            continue;
          }
          if (r.at("key") == "PrefKeyServicesEnabled" &&
              r.at("value") == INTEGER(1)) {
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

int getContentCachingStatus() {
  auto contentCachingStatus =
      SQL::selectAllFrom("plist", "path", EQUALS, kContentCachingPath);
  if (contentCachingStatus.empty()) {
    return 0;
  }
  for (const auto& row : contentCachingStatus) {
    if (row.find("key") == row.end() || row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "Activated" && row.at("value") == INTEGER(1)) {
      return 1;
    }
  }
  return 0;
}

QueryData genSharingPreferences(QueryContext& context) {
  Row r;
  r["screen_sharing"] = INTEGER(getScreenSharingStatus());
  r["file_sharing"] = INTEGER(getFileSharingStatus());
  r["printer_sharing"] = INTEGER(getPrinterSharingStatus());
  r["remote_login"] = INTEGER(getRemoteLoginStatus());
  r["remote_management"] = INTEGER(getRemoteManagementStatus());
  r["remote_apple_events"] = INTEGER(getRemoteAppleEventStatus());
  r["internet_sharing"] = INTEGER(getInterNetSharingStatus());
  r["bluetooth_sharing"] = INTEGER(getBluetoothSharingStatus());
  r["disc_sharing"] = INTEGER(getDiscSharingStatus());
  r["content_caching"] = INTEGER(getContentCachingStatus());
  return {r};
}

} // namespace tables
} // namespace osquery
