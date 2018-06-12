/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <Windows.h>

#include <osquery/core.h>
#include <osquery/core/windows/kobjhandle.h>
#include <osquery/core/windows/ntapi.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

// the windows object namespace consists of nested directories,
// beginning with \
//
// each directory consists of zero or more entries, each of which consists
// of an unqualified object name and an object type name.  both are
// represented by the windows kernel as UTF-16 strings
//
// the pair of object name and object type name are used frequently
// in this module.  use a std::pair of std::wstrings to represent this
// pair and provide a simpler name
//
// this type definition is internal to this module and meant as a
// type to be used with the rest of osquery.  this note is important
// because osquery uses UTF-8 encoded std::strings throughout.  Because
// windows uses UTF-16 strings, which are most easily represented by
// std::wstring, std::wstrings are used internally to this module and
// converted to UTF-8 encoded std::strings when communicating with the
// rest of osquery
//
typedef std::pair<std::wstring, std::wstring> obj_name_type_pair;

// helper to convert a std::wstring to an integer
// std::stoi can throw, and std::stol doesn't support std::wstring
static int safe_wstr_to_int(std::wstring str) {
  try {
    return std::stoi(str);
  }
  catch (const std::out_of_range&) {
    return 0;
  }
  catch (const std::invalid_argument&) {
    return 0;
  }
}

// enumerate all objects in the Windows object namespace
// does not provide support for recursion
//
// example at:
//    http://pastebin.com/embed_js/zhmJTffK
//    https://randomsourcecode.wordpress.com/2015/03/14/enumerating-deviceobjects-from-user-mode/
//    https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
//
std::vector<obj_name_type_pair> EnumerateObjectNamespace(std::wstring directory) {
  std::vector<obj_name_type_pair> objects;

  // look up addresses of NtQueryDirectoryObject and
  // NtQuerySymbolicLinkObject.  Both are exported from ntdll
  //
  // NtQueryDirectoryObject is documented on MSDN, there is no
  // associated header or import library
  NTQUERYDIRECTORYOBJECT NtQueryDirectoryObject =
      (NTQUERYDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                             "NtQueryDirectoryObject");
  if (NULL == NtQueryDirectoryObject) {
    return objects;
  }

  // open the caller-provided root directory
  // kdo will manage the resultant HANDLE, which is also used to query
  // for object name and object type name pairs below
  KObjHandle kdo;
  if (!kdo.openDirObj(directory)) {
    return objects;
  }

  // iterator index is incremented by NtQueryDirectoryObject
  for (DWORD index = 0;;) {
    BYTE rgDirObjInfoBuffer[1024 * 8] = {0};
    POBJDIR_INFORMATION pObjDirInfo = (POBJDIR_INFORMATION)rgDirObjInfoBuffer;

    //  get the name and type of the index'th object in the directory
    NTSTATUS ntStatus = NtQueryDirectoryObject(kdo.getAsHandle(),
                                               pObjDirInfo,
                                               sizeof(rgDirObjInfoBuffer),
                                               TRUE,
                                               FALSE,
                                               &index,
                                               NULL);
    if (STATUS_SUCCESS != ntStatus) {
      break;
    }

    obj_name_type_pair object;
    object.first = (pObjDirInfo->ObjectName.Buffer);
    object.second = (pObjDirInfo->ObjectTypeName.Buffer);

    objects.push_back(object);
  }

  return objects;
}

// enumerate all objects in a given windows terminal services session
//
// objects are found in the windows object directory
// "\Sessions\BNOLINKS\<sessionnum>"
//
std::vector<obj_name_type_pair>
EnumerateBaseNamedObjectsLinks(std::wstring session_num,
                               std::wstring object_type) {
  std::vector<obj_name_type_pair> objects;

  // look up NtQuerySymbolicLinkObject as exported from ntdll
  NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject =
      (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                                "NtQuerySymbolicLinkObject");
  if (NULL == NtQuerySymbolicLinkObject) {
    return objects;
  }

  // by convention, we expect there to be <n> objects in \Sessions\BNOLINKS with
  // the following three characteristics:
  //
  //   (1) the object name is the string representation of of an active terminal
  //       services session id.  this means we expect the object name to be a
  //       string representation of an integer
  //
  //   (2) the object type name be "SymbolicLink"
  //
  //   (3) the symbolic link point to a directory object
  //
  // validate in this order
  //

  // validate (1)
  //
  // validate that this appears to be a valid terminal services session id
  // another approach is to enumerate windows terminal services sessions with
  // WTSEnumerateSessions and validate against that list
  //
  if (!(L"0" == session_num || safe_wstr_to_int(session_num) > 0)) {
    return objects;
  }

  // validate (2)
  //
  // validate that the object type is "SymbolicLink"
  //
  if (L"SymbolicLink" != object_type) {
    return objects;
  }

  // at this point we have SymbolicLink with a name matching a terminal services
  // session id.  now build the fully qualified object path
  std::wstring qualifiedpath = L"\\Sessions\\BNOLINKS\\" + session_num;

  // open the symbolic link itself in order to determine the target of the link
  KObjHandle slo;
  if (!slo.openSymLinkObj(qualifiedpath)) {
    return objects;
  }

  UNICODE_STRING usSymbolicLinkTarget;
  WCHAR wzTargetLinkBuffer[MAX_PATH];
  usSymbolicLinkTarget.Buffer = wzTargetLinkBuffer;
  usSymbolicLinkTarget.Length = 0;
  usSymbolicLinkTarget.MaximumLength = MAX_PATH;

  NTSTATUS ntStatus =
      NtQuerySymbolicLinkObject(slo.getAsHandle(), &usSymbolicLinkTarget, NULL);
  if (STATUS_SUCCESS != ntStatus) {
    return objects;
  }

  return EnumerateObjectNamespace(usSymbolicLinkTarget.Buffer);
}

QueryData genBaseNamedObjects(QueryContext& context) {
  QueryData results;

  // enumerate the base named objects in each terminal services session
  auto sessions = EnumerateObjectNamespace(L"\\Sessions\\BNOLINKS");

  for (auto& session : sessions) {
    auto objects =
        EnumerateBaseNamedObjectsLinks(session.first, session.second);

    for (auto& object : objects) {
      Row r;
      r["session_id"] = INTEGER(safe_wstr_to_int(session.first));
      r["object_name"] = wstringToString(object.first.c_str());
      r["object_type"] = wstringToString(object.second.c_str());

      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
