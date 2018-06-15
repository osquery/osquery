/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <AccCtrl.h>
#include <Aclapi.h>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace alg = boost::algorithm;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// map to get access mode string
static const std::unordered_map<ACCESS_MODE, std::string> kAccessModeToStr = {
    {NOT_USED_ACCESS, "Not Used"},
    {GRANT_ACCESS, "Grant"},
    {SET_ACCESS, "Set"},
    {DENY_ACCESS, "Deny"},
    {REVOKE_ACCESS, "Revoke"},
    {SET_AUDIT_SUCCESS, "Set Audit Success"},
    {SET_AUDIT_FAILURE, "Set Audit Failure"}};

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
     {INHERIT_NO_PROPAGATE, "Inherit No Propagate"},
     {INHERIT_ONLY, "Inherit Only"},
     {OBJECT_INHERIT_ACE, "Object Inherit Ace"},
     {SUB_CONTAINERS_AND_OBJECTS_INHERIT, "Sub containers and Objects Inherit"},
     {NO_INHERITANCE, "No Inheritence"}};

// helper function to build access string from permission bit mask
std::string accessPermsToStr(const unsigned long pmask) {
  std::vector<std::string> permList;

  for (auto const& perm : kPermVals) {
    if ((pmask & perm.first) != 0) {
      permList.push_back(perm.second);
    }
  }

  return alg::join(permList, ",");
}

// helper function to get account/group name from trustee
std::string trusteeToStr(const TRUSTEE& trustee) {
  // Max username length for Windows
  const unsigned long maxBuffSize = 256;
  char name[maxBuffSize];
  char domain[maxBuffSize];
  SID_NAME_USE accountType;

  switch (trustee.TrusteeForm) {
  case TRUSTEE_IS_SID: {
    // get the name from the SID
    PSID psid = trustee.ptstrName;
    auto sizea = maxBuffSize;
    auto r = LookupAccountSid(
        nullptr, psid, name, &sizea, domain, &size, &accountType);
    if (r == FALSE) {
      VLOG(1) << "LookupAccountSid error: " << GetLastError();
      return "";
    } else {
      return name;
    }
  }
  case TRUSTEE_IS_NAME:
    // get the name from ptstrName
    return trustee.ptstrName;
  case TRUSTEE_BAD_FORM:
    // Indicates a trustee form that is not valid.
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa379638(v=vs.85).aspx
    return "Invalid";
  case TRUSTEE_IS_OBJECTS_AND_SID: {
    // ptstrName member is a pointer to an OBJECTS_AND_SID struct
    auto psid = reinterpret_cast<POBJECTS_AND_SID>(trustee.ptstrName)->pSid;
    auto sizeb = maxBuffSize;
    auto r = LookupAccountSid(
        nullptr, psid, name, &sizeb, domain, &size, &accountType);
    if (r == FALSE) {
      VLOG(1) << "LookupAccountSid error: " << GetLastError();
      return "";
    } else {
      return name;
    }
  }
  case TRUSTEE_IS_OBJECTS_AND_NAME:
    // ptstrName member is a pointer to an OBJECTS_AND_NAME struct
    return reinterpret_cast<OBJECTS_AND_NAME_*>(trustee.ptstrName)->ptstrName;
  default:
    return "";
  }
}

QueryData genNtfsAclPerms(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& pathString : paths) {
    if (!fs::exists(pathString)) {
      continue;
    }
    // Get a pointer to the existing DACL.
    PACL dacl = nullptr;
    auto result = GetNamedSecurityInfo(pathString.c_str(),
                                       SE_FILE_OBJECT,
                                       DACL_SECURITY_INFORMATION,
                                       nullptr,
                                       nullptr,
                                       &dacl,
                                       nullptr,
                                       nullptr);
    if (ERROR_SUCCESS != result) {
      VLOG(1) << "GetExplicitEnteriesFromAcl Error " << result;
      continue;
    }

    // get list of ACEs from DACL pointer
    unsigned long aceCount = 0;
    PEXPLICIT_ACCESS aceList = nullptr;
    result = GetExplicitEntriesFromAcl(dacl, &aceCount, &aceList);
    if (ERROR_SUCCESS != result) {
      VLOG(1) << "GetExplicitEnteriesFromAcl Error " << result;
      continue;
    }

    // Loop through list of entries
    auto aceItem = aceList;
    for (unsigned long aceIndex = 0; aceIndex < aceCount;
         aceItem++, aceIndex++) {
      Row r;

      auto perms = accessPermsToStr(aceItem->grfAccessPermissions);
      auto accessMode = kAccessModeToStr.find(aceItem->grfAccessMode)->second;
      auto inheritedFrom =
          kInheritanceToStr.find(aceItem->grfInheritance)->second;
      auto trusteeName = trusteeToStr(aceItem->Trustee);

      r["path"] = TEXT(pathString);
      r["type"] = TEXT(accessMode);
      r["principal"] = TEXT(trusteeName);
      r["access"] = TEXT(perms);
      r["inherited_from"] = TEXT(inheritedFrom);
      results.push_back(std::move(r));
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
