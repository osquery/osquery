/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <AccCtrl.h>
#include <Aclapi.h>

#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/system/system.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace alg = boost::algorithm;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

static const unsigned long maxBuffSize = 256;

// map to get access mode string
static const std::unordered_map<BYTE, std::string> kAccessCodeToStr = {
    {ACCESS_ALLOWED_ACE_TYPE, "Grant"},
    {ACCESS_DENIED_ACE_TYPE, "Deny"},
    {SYSTEM_AUDIT_ACE_TYPE, "Audit"},
    {SYSTEM_ALARM_ACE_TYPE, "Alarm"},
    {ACCESS_ALLOWED_COMPOUND_ACE_TYPE, "Compounded Grant"},
    {ACCESS_ALLOWED_OBJECT_ACE_TYPE, "Grant Object"},
    {ACCESS_DENIED_OBJECT_ACE_TYPE, "Deny Object"},
    {SYSTEM_AUDIT_OBJECT_ACE_TYPE, "Audit Object"},
    {SYSTEM_ALARM_OBJECT_ACE_TYPE, "Alarm Object"},
    {ACCESS_ALLOWED_CALLBACK_ACE_TYPE, "Grant with Callback"},
    {ACCESS_DENIED_CALLBACK_ACE_TYPE, "Deny with Callback"},
    {ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, "Grant Object with Callback"},
    {ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, "Deny Object with Callback"},
    {SYSTEM_AUDIT_CALLBACK_ACE_TYPE, "Audit with Callback"},
    {SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, "Audit Object with Callback"},
    {SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, "Alarm Object with Callback"},
    {SYSTEM_MANDATORY_LABEL_ACE_TYPE, "Mandatory Label"},
    {SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, "Resource Attribute"},
    {SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, "Scoped Policy"},
    {SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, "Process trust Label"}};

// map to build access string
static const std::map<unsigned long, std::string> kPermVals = {
    {DELETE, "Delete"},
    {READ_CONTROL, "Read Control"},
    {WRITE_DAC, "Write DAC"},
    {WRITE_OWNER, "Write Owner"},
    {SYNCHRONIZE, "Synchronize"},
    {STANDARD_RIGHTS_REQUIRED, "Std Rights Required"},
    {STANDARD_RIGHTS_ALL, "Std Rights All"},
    {SPECIFIC_RIGHTS_ALL, "Specific Rights All"},
    {ACCESS_SYSTEM_SECURITY, "Access System Security"},
    {MAXIMUM_ALLOWED, "Maximum Allowed"},
    {GENERIC_READ, "Generic Read"},
    {GENERIC_WRITE, "Generic Write"},
    {GENERIC_EXECUTE, "Generic Execute"},
    {GENERIC_ALL, "Generic All"}};

// map to get inheritance string
static const std::unordered_map<unsigned long, std::string> kInheritanceToStr =
    {{CONTAINER_INHERIT_ACE, "Container Inherit Ace"},
     {NO_PROPAGATE_INHERIT_ACE, "Inherit No Propagate"},
     {INHERIT_ONLY_ACE, "Inherit Only"},
     {OBJECT_INHERIT_ACE, "Object Inherit Ace"},
     {SUB_CONTAINERS_AND_OBJECTS_INHERIT, "Sub containers and Objects Inherit"},
     {INHERITED_ACE, "Inherited Ace"}};

std::string accessCodeToStr(ACE_HEADER aceHeader) {
  std::string sAccessCode("");
  auto it = kAccessCodeToStr.find(aceHeader.AceType);
  if (it != kAccessCodeToStr.end()) {
    sAccessCode = it->second;

    // Audit / Alarm success
    if (aceHeader.AceType & SUCCESSFUL_ACCESS_ACE_FLAG) {
      sAccessCode.append(" Success");
    } else if (aceHeader.AceType & FAILED_ACCESS_ACE_FLAG) {
      sAccessCode.append(" Failure");
    }
  }
  return sAccessCode;
}

std::string inheritCodeToStr(BYTE aceFlags) {
  std::string sInheritCode("No Inheritance");
  auto it = kInheritanceToStr.find(aceFlags & VALID_INHERIT_FLAGS);
  if (it != kInheritanceToStr.end()) {
    sInheritCode = it->second;
  }
  return sInheritCode;
}

std::string accessPermsToStr(const unsigned long pmask) {
  std::vector<std::string> permList;

  for (auto const& perm : kPermVals) {
    if ((pmask & perm.first) != 0) {
      permList.push_back(perm.second);
    }
  }

  return alg::join(permList, ",");
}

std::string pSidToStrUserName(PSID psid) {
  unsigned long unameSize = 0;
  unsigned long domNameSize = 1;
  SID_NAME_USE accountType;

  // LookupAccountSid first gets the size of the username buff required.
  LookupAccountSidW(
      nullptr, psid, nullptr, &unameSize, nullptr, &domNameSize, &accountType);

  std::vector<wchar_t> uname(unameSize);
  std::vector<wchar_t> domName(domNameSize);
  BOOL bSuccess = LookupAccountSidW(nullptr,
                                    psid,
                                    uname.data(),
                                    &unameSize,
                                    domName.data(),
                                    &domNameSize,
                                    &accountType);
  if (bSuccess == FALSE) {
    VLOG(1) << "LookupAccountSid Error " << GetLastError();
    return "";
  } else {
    return wstringToString(uname.data());
  }
}

QueryData genNtfsAclPerms(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& pathString : paths) {
    if (!fs::exists(pathString)) {
      continue;
    }
    std::wstring wsPath(stringToWstring(pathString));
    // Get a pointer to the existing DACL.
    PACL dacl = nullptr;
    auto result = GetNamedSecurityInfoW(wsPath.c_str(),
                                        SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION,
                                        nullptr,
                                        nullptr,
                                        &dacl,
                                        nullptr,
                                        nullptr);
    if (ERROR_SUCCESS != result) {
      VLOG(1) << "GetNamedSecurityInfo Error " << result;
      continue;
    }

    ACCESS_ALLOWED_ACE* pAce = NULL;
    // Loop through the ACEs and display the information.
    for (WORD cAce = 0; cAce < dacl->AceCount; cAce++) {
      Row r;
      // Get ACE
      if (GetAce(dacl, cAce, (LPVOID*)&pAce) == FALSE) {
        VLOG(1) << "GetAce Error " << GetLastError();
        continue;
      }
      auto trusteeName = pSidToStrUserName(&pAce->SidStart);
      auto perms = accessPermsToStr(pAce->Mask);
      auto aceType = accessCodeToStr(pAce->Header);
      auto aceFlags = inheritCodeToStr(pAce->Header.AceFlags);

      r["path"] = SQL_TEXT(pathString);
      r["type"] = SQL_TEXT(aceType);
      r["principal"] = SQL_TEXT(trusteeName);
      r["access"] = SQL_TEXT(perms);
      r["inherited_from"] = SQL_TEXT(aceFlags);
      results.push_back(std::move(r));
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
