/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"
#include "osquery/tables/system/darwin/sharing.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kInternetSharingPath = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist";
const std::string kRemoteAppleManagementPath = "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd";
const std::string kRemoteBluetoothSharingPath = "/Library/Preferences/ByHost/";
const std::string kRemoteBluetoothSharingPattern = "com.apple.Bluetooth.%";


bool remoteAppleManagementPlistExists() {
  auto internet_sharing_status = SQL::selectAllFrom("file", "path", EQUALS, kRemoteAppleManagementPath);
  if (internet_sharing_status.empty()) {
    return false;
  }
  return true;
}

int getScreenSharingStatus() {
  Boolean persistent;
  if (remoteAppleManagementPlistExists()) {
    return 0;
  } else {
    return SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.apple.screensharing"), &persistent);
  }
}

int getRemoteManagementStatus() {
  return remoteAppleManagementPlistExists() ? 1 : 0;
}

int getFileSharingStatus() {
  Boolean persistent;
  int smbStatus = SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.apple.smbd"), &persistent);
  int fileServerStatus = SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.apple.AppleFileServer"), &persistent);
  if (smbStatus == 1 || fileServerStatus == 1) {
    return 1;
  } else {
    return 0;
  }
}

int getRemoteLoginStatus() {
  Boolean persistent;
  return SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.openssh.sshd"), &persistent);
}

int getRemoteAppleEventStatus() {
  Boolean persistent;
  return SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.apple.AEServer"), &persistent);
}

int getDiscSharingStatus() {
  Boolean persistent;
  return SMJobIsEnabled(kSMDomainSystemLaunchd, CFSTR("com.apple.ODSAgent"), &persistent);
}

int getPrinterSharingStatus() {
  http_t *cups;
  int num_settings = 0;
  cups_option_t *settings = NULL;
  const char *value;

  cups = httpConnect2(cupsServer(), ippPort(), NULL, AF_INET, cupsEncryption(), 1, 30000, NULL);
  if (cups != NULL) {
    int ret = cupsAdminGetServerSettings(cups, &num_settings, &settings);
    if (ret != 0) {
      if ((value = cupsGetOption("_share_printers", num_settings, settings)) && value != NULL) {
        return *value == '1' ? 1 : 0;
      }
      cupsFreeOptions(num_settings, settings);
    } else {
      VLOG(1) << "ERROR: Unable to get CUPS server settings: " << cupsLastErrorString();
    }
    httpClose(cups);
  }
  return 0;
}

int getInterNetSharingStatus() {
  auto internet_sharing_status = SQL::selectAllFrom("plist", "path", EQUALS, kInternetSharingPath);
  if (internet_sharing_status.empty()) {
    return 0;
  }
  for (const auto& row : internet_sharing_status) {
    if (row.find("key") == row.end() || row.find("subkey") == row.end() || row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "NAT" && row.at("subkey") == "Enabled" && row.at("value") == INTEGER(1)) {
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
      if (!resolveFilePattern(dir / kRemoteBluetoothSharingPattern, paths).ok()) {
        continue;
      }

      for (const auto& bluetoothSharing_path : paths) {
        auto bluetoothSharingStatus = SQL::selectAllFrom("plist", "path", EQUALS, bluetoothSharing_path);
        if (bluetoothSharingStatus.empty()) {
          continue;
        }
        for (const auto& r : bluetoothSharingStatus) {
          if (r.find("key") == row.end() || row.find("value") == r.end()) {
            continue;
          }
          if (r.at("key") == "PrefKeyServicesEnabled" && r.at("value") == INTEGER(1)) {
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

QueryData genSharing(QueryContext& context) {
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
  return {r};
}


} // namespace tables
} // namespace osquery
