/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <windows.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <string>
#include <map>
#include <vector>

#include <osquery/logger.h>
#include <osquery/tables.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>

namespace alg = boost::algorithm;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// helper function to get access mode string
std::string accessModeToStr(const _ACCESS_MODE& accessMode) {
	switch (accessMode) {
	case NOT_USED_ACCESS:
		return "Not Used";
	case GRANT_ACCESS:
		return "Grant";
	case SET_ACCESS:
		return "Set";
	case DENY_ACCESS:
		return "Deny";
	case REVOKE_ACCESS:
		return "Revoke";
	case SET_AUDIT_SUCCESS:
		return "Set Audit Success";
	case SET_AUDIT_FAILURE:
		return "Set Audit Failure";
	default:
		return "Unknown";
	}
}

// helper function to build access string from permission bit mask
std::string accessPermsToStr(const unsigned long pmask) {
	std::vector<std::string> permList;
	std::string permStr = "";
	const std::map<unsigned long, std::string> permVals = {
		{ DELETE                         ,"Delete" },
		{ READ_CONTROL                   ,"Read Control" },
		{ WRITE_DAC                      ,"Write DAC" },
		{ WRITE_OWNER                    ,"Write Owner" },
		{ SYNCHRONIZE                    ,"Synchronize" },
		{ STANDARD_RIGHTS_REQUIRED       ,"Std Rights Required" },
		{ STANDARD_RIGHTS_ALL            ,"Std Rights All" },
		{ SPECIFIC_RIGHTS_ALL            ,"Specific Rights All" },
		{ ACCESS_SYSTEM_SECURITY         ,"Access System Security" },
		{ MAXIMUM_ALLOWED                ,"Maximum Allowed" },
		{ GENERIC_READ                   ,"Generic Read" },
		{ GENERIC_WRITE                  ,"Generic Write" },
		{ GENERIC_EXECUTE                ,"Generic Execute" },
		{ GENERIC_ALL                    ,"Generic All" }
	};

	for (auto const& perm : permVals) {
		if ((pmask & perm.first) != 0)
			permList.push_back(perm.second);
	}

	permStr = alg::join(permList, ",");
	return permStr;
}

// helper function to convert inheritance type to string
std::string inheritanceToStr(const unsigned long i) {
	switch (i) {
	case CONTAINER_INHERIT_ACE: // equivalent to SUB_CONTAINERS_ONLY_INHERIT
		return "Container Inherit Ace";
	case INHERIT_NO_PROPAGATE: // equivalent to NO_PROPAGATE_INHERIT_ACE
		return "Inherit No Propagate";
	case INHERIT_ONLY: // equivalent to INHERIT_ONLY_ACE
		return "Inherit Only";
	case OBJECT_INHERIT_ACE: // equivalent to SUB_OBJECTS_ONLY_INHERIT
		return "Object Inherit Ace";
	case SUB_CONTAINERS_AND_OBJECTS_INHERIT:
		return "Sub containers and Objects Inherit";
	case NO_INHERITANCE:
		return "No Inheritence";
	default:
		return "Other";
	}
}

// helper function to get account/group name from trustee
std::string trusteeToStr(const TRUSTEE& t) {
	char name[256];
	char domain[256];
	unsigned long size = 256;
	//bool r;
	SID_NAME_USE accountType;

	switch (t.TrusteeForm) {
	case TRUSTEE_IS_SID:
		// get the name from the SID
		if (!LookupAccountSid(NULL, 
				(PSID) t.ptstrName, name,
				&size,
                domain,
                &size,
                &accountType)) {
			//sprintf("LookupAccountSid error: %u\n", GetLastError());
            TLOG << "LookupAccountSid error: " << GetLastError();
		}
		else {
			return name;
		}
	case TRUSTEE_IS_NAME:
		// get the name from ptstrName
		return t.ptstrName;
	case TRUSTEE_BAD_FORM:
		// invalid
		return "Invalid";
	case TRUSTEE_IS_OBJECTS_AND_SID:
		// ptstrName member is a pointer to an OBJECTS_AND_SID struct
        if (!LookupAccountSid(
				NULL,
                (PSID)((OBJECTS_AND_SID*)t.ptstrName)->pSid,
                name,
                &size,
                domain,
                &size,
                &accountType)) {
			//printf("LookupAccountSid error: %u\n", GetLastError());
            TLOG << "LookupAccountSid error: " << GetLastError();
		}
		else {
			return name;
		}
	case TRUSTEE_IS_OBJECTS_AND_NAME:
		// ptstrName member is a pointer to an OBJECTS_AND_NAME struct
		return ((OBJECTS_AND_NAME_*) t.ptstrName)->ptstrName;
	default:
		return "";
	}
}

QueryData genNTFSACLPerms(QueryContext& context) {
  QueryData results;

	std::string ObjName;
	unsigned long result = 0;
	PACL DACL = NULL;
	PEXPLICIT_ACCESS aceList = NULL, aceItem;
	unsigned long aceCount, aceIndex;

	auto paths = context.constraints["path"].getAll(EQUALS);
    for (const auto& path_string : paths) {
          if (fs::exists(path_string)) {
				fs::path ObjName = path_string;

				// Get a pointer to the existing DACL.

                result = GetNamedSecurityInfo(path_string.c_str(),
                                                SE_FILE_OBJECT,
                                                DACL_SECURITY_INFORMATION,
                                                NULL,
                                                NULL,
                                                &DACL,
                                                NULL,
                                                NULL);
                if (ERROR_SUCCESS != result) {
                    //printf("GetNamedSecurityInfo Error %u\n", result);
					TLOG << "GetExplicitEnteriesFromAcl Error " << result;
                }

				// get list of ACEs from DACL pointer
                result = GetExplicitEntriesFromAcl(
                    DACL, &aceCount, &aceList);
                if (ERROR_SUCCESS != result) {
                    //printf("GetExplicitEnteriesFromAcl Error %u\n",
                    //        result);
					TLOG << "GetExplicitEnteriesFromAcl Error " << result;
                }

                // Loop through list of entries

                aceItem = aceList;
                // printf("AccessMode | TrusteeName | AccessPermissions
                // | Inheritence\n");
                for (aceIndex = 0; aceIndex < aceCount; aceItem++) {
                    Row r;
                    std::string accessMode;
                    std::string inheritedFrom;
                    std::string perms;
                    std::string trusteeName;

                    perms =
                        accessPermsToStr(aceItem->grfAccessPermissions);
                    accessMode = accessModeToStr(aceItem->grfAccessMode);
                    inheritedFrom =
                        inheritanceToStr(aceItem->grfInheritance);
                    trusteeName = trusteeToStr(aceItem->Trustee);

                    r["path"] = TEXT(path_string);
                    r["type"] = TEXT(accessMode);
                    r["principal"] = TEXT(trusteeName);
                    r["access"] = TEXT(perms);
                    r["inherited_from"] = TEXT(inheritedFrom);
                    results.push_back(r);

                    aceIndex++;
                }
		  }	
	}

  return results;
}

}
}