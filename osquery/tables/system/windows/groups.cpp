/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/core/windows/process_ops.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/core/conversions.h"

namespace osquery {

// Get the relative identifier (RID) from a security identifier (SID):
unsigned long getRidFromSid(PSID sidPtr) {
  BYTE* countPtr = GetSidSubAuthorityCount(sidPtr);
  unsigned long indexOfRid = static_cast<unsigned long>(*countPtr - 1);
  unsigned long* ridPtr = GetSidSubAuthority(sidPtr, indexOfRid);
  return *ridPtr;
}

namespace tables {

std::unique_ptr<BYTE[]> GetSid(LPCWSTR accountName) {
  // Validate the input parameters.
  if (accountName == nullptr) {
    LOG(INFO) << "GetSid(): no account name provided.";
    return nullptr;
  }

  // Call LookupAccountNameW() once to retrieve the necessary buffer sizes for
  // the SID (in bytes) and the domain name (in TCHARS):
  unsigned long sidBufferSize = 0;
  unsigned long domainNameSize = 0;
  auto eSidType = SidTypeUnknown;
  LookupAccountNameW(nullptr,
                     accountName,
                     nullptr,
                     &sidBufferSize,
                     nullptr,
                     &domainNameSize,
                     &eSidType);

  // Allocate sufficient buffers for the (binary data) SID and the (wide string)
  // domain name:
  auto sidBuffer = std::make_unique<BYTE[]>(sidBufferSize);
  std::vector<wchar_t> domainName(domainNameSize);

  // Call LookupAccountNameW() a second time to actually obtain the SID for the
  // given account name:
  auto ret = LookupAccountNameW(nullptr,
                                accountName,
                                sidBuffer.get(),
                                &sidBufferSize,
                                domainName.data(),
                                &domainNameSize,
                                &eSidType);
  if (ret == 0) {
    LOG(INFO) << "Failed to LookupAccountNameW(): " << accountName;
  } else if (IsValidSid(sidBuffer.get()) == FALSE) {
    LOG(INFO) << "The SID for " << accountName << " is invalid.";
  }

  return sidBuffer; // Implicit move operation. Caller "owns" returned pointer.
}

void processLocalGroups(QueryData& results) {
  unsigned long groupInfoLevel = 1;
  unsigned long numGroupsRead = 0;
  unsigned long totalGroups = 0;
  unsigned long resumeHandle = 0;
  unsigned long ret = 0;
  LOCALGROUP_INFO_1* lginfo = nullptr;

  std::unique_ptr<BYTE[]> sidSmartPtr = nullptr;
  PSID sidPtr = nullptr;

  do {
    ret = NetLocalGroupEnum(nullptr,
                            groupInfoLevel,
                            (LPBYTE*)&lginfo,
                            MAX_PREFERRED_LENGTH,
                            &numGroupsRead,
                            &totalGroups,
                            nullptr);

    if ((ret == NERR_Success || ret == ERROR_MORE_DATA) && lginfo != nullptr) {
      for (size_t i = 0; i < numGroupsRead; i++) {
        Row r;
        sidSmartPtr = GetSid(lginfo[i].lgrpi1_name);

        if (sidSmartPtr != nullptr) {
          sidPtr = static_cast<PSID>(sidSmartPtr.get());
        } else {
          // nullptr still valid, just results in blank fields
          sidPtr = nullptr;
        }

        // Windows' extended schema, including full SID and comment strings:
        r["group_sid"] = psidToString(sidPtr);
        r["comment"] = wstringToString(lginfo[i].lgrpi1_comment);

        // Common schema, normalizing group information with POSIX:
        r["gid"] = INTEGER(getRidFromSid(sidPtr));
        r["gid_signed"] = INTEGER(getRidFromSid(sidPtr));
        r["groupname"] = wstringToString(lginfo[i].lgrpi1_name);
        results.push_back(r);
      }
    } else {
      LOG(INFO) << "NetLocalGroupEnum failed with return value: " << ret;
    }
    if (lginfo != nullptr) {
      NetApiBufferFree(lginfo);
    }
  } while (ret == ERROR_MORE_DATA);
}

QueryData genGroups(QueryContext& context) {
  QueryData results;

  processLocalGroups(results);

  return results;
}
} // namespace tables
} // namespace osquery