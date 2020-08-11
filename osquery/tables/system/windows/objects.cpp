/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include "osquery/core/windows/handle.h"
#include "osquery/core/windows/ntapi.h"
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

// the windows object namespace consists of nested directories,
// rooted at \
//
// each directory consists of zero or more entries, each of which consists
// of an unqualified object name and an object type name.  both are
// represented by the windows kernel as UTF-16 strings
//
// the pair of object name and object type name are used frequently
// in this module.  use a std::pair of std::wstrings to represent this
// pair and provide a simpler name
//
// this type definition is internal to this module and not meant as a
// type to be used with the rest of osquery.  this note is important
// because osquery uses UTF-8 encoded std::strings throughout.  Because
// windows uses UTF-16 strings, which are most easily represented by
// std::wstring, std::wstrings are used internally to this module and
// converted to UTF-8 encoded std::strings when interfacing with the
// rest of osquery
//
using obj_name_type_pair = std::pair<std::wstring, std::wstring>;

// arbitrary upper bound on number of supported objects in a single
// directory to query.  windows provides a means to query a single object
// at a time via an index; this arbitrary upper bound is a backstop
//
static const unsigned long kMaxSupportedObjects = 1024 * 1024;

// arbitrary buffer size to be used when querying for a single
// object-name--object-type-name pair with NtQueryDirectoryObject
//
static const unsigned long kObjBufSize = 8 * 1024;

// \Sessions\BNOLINKS is the hardcoded object directory where
// symbolic links to the directories of Base Named Objects on a
// per-terminal-services-session are found
//
const std::wstring kBnoLinks{L"\\Sessions\\BNOLINKS"};

// enumerate all objects in the Windows object namespace
// does not provide support for recursion
//
// example at:
//    http://pastebin.com/embed_js/zhmJTffK
//    https://randomsourcecode.wordpress.com/2015/03/14/enumerating-deviceobjects-from-user-mode/
//    https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
//
Status enumerateObjectNamespace(const std::wstring& directory,
                                std::vector<obj_name_type_pair>& objects) {
  // look up addresses of NtQueryDirectoryObject and
  // NtQuerySymbolicLinkObject.  Both are exported from ntdll
  //
  // NtQueryDirectoryObject is documented on MSDN, there is no
  // associated header or import library
  //
  auto NtQueryDirectoryObject = reinterpret_cast<NTQUERYDIRECTORYOBJECT>(
      GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryDirectoryObject"));
  if (nullptr == NtQueryDirectoryObject) {
    return Status(GetLastError(), "Unable to find NtQueryDirectoryObject");
  }

  // open the caller-provided root directory
  // kdo will manage the resultant HANDLE, which is also used to query
  // for object name and object type name pairs below
  //
  Handle kdo;
  auto status = kdo.openDirObj(directory);
  if (!status.ok()) {
    VLOG(1) << L"Unable to open object directory: " << status.getCode();
    return status;
  }

  // iterator index is incremented by NtQueryDirectoryObject
  // for safety, bail out at kMaxSupportedObjects
  //
  for (unsigned long index = 0; index < kMaxSupportedObjects;) {
    unsigned char obj_buf[kObjBufSize] = {0};
    auto pObjDirInfo = reinterpret_cast<POBJDIR_INFORMATION>(obj_buf);

    //  get the name and type of the index'th object in the directory
    //
    auto ntStatus = NtQueryDirectoryObject(
        kdo.getAsHandle(), pObjDirInfo, kObjBufSize, TRUE, FALSE, &index, NULL);
    if (STATUS_SUCCESS != ntStatus) {
      break;
    }

    obj_name_type_pair object;
    object.first = (pObjDirInfo->ObjectName.Buffer);
    object.second = (pObjDirInfo->ObjectTypeName.Buffer);

    objects.push_back(object);
  }

  return Status::success();
}

// enumerate all objects in a given windows terminal services session
//
// objects are found in the windows object directory
// "\Sessions\BNOLINKS\<sessionnum>"
//
Status enumerateBaseNamedObjectsLinks(
    const std::wstring& session_num,
    const std::wstring& object_type,
    std::vector<obj_name_type_pair>& objects) {
  // look up NtQuerySymbolicLinkObject as exported from ntdll
  //
  auto NtQuerySymbolicLinkObject = reinterpret_cast<NTQUERYSYMBOLICLINKOBJECT>(
      GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySymbolicLinkObject"));
  if (nullptr == NtQuerySymbolicLinkObject) {
    return Status(GetLastError(), "Cannot locate NtQuerySymbolicLinkObject");
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
  //   (3) the symbolic link references a directory object
  //
  // the validation of (1) is optional as the means to validate (3) will
  // ensure that the directory object is valid
  //

  // validate (2)
  //
  // validate that the object type name is "SymbolicLink"
  //
  if (L"SymbolicLink" != object_type) {
    return Status(ERROR_INVALID_PARAMETER, "Unexpected Object Type");
  }

  // at this point we have SymbolicLink with a name matching a terminal services
  // session id.   build the fully qualified object path
  //
  std::wstring qualifiedpath = kBnoLinks + L"\\" + session_num;

  // open the symbolic link itself in order to determine the target of the link
  //
  Handle slo;
  auto status = slo.openSymLinkObj(qualifiedpath);
  if (!status.ok()) {
    VLOG(1) << L"Unable to open symbolic link object: " << status.getCode();
    return status;
  }

  UNICODE_STRING usSymbolicLinkTarget;
  WCHAR wzTargetLinkBuffer[MAX_PATH] = {L'\0'};
  usSymbolicLinkTarget.Buffer = wzTargetLinkBuffer;
  usSymbolicLinkTarget.Length = 0;
  usSymbolicLinkTarget.MaximumLength = MAX_PATH;

  auto ntStatus =
      NtQuerySymbolicLinkObject(slo.getAsHandle(), &usSymbolicLinkTarget, NULL);
  if (STATUS_SUCCESS != ntStatus) {
    return Status(ntStatus, "NtQuerySymbolicLink failed");
  }

  return enumerateObjectNamespace(usSymbolicLinkTarget.Buffer, objects);
}

QueryData genBaseNamedObjects(QueryContext& context) {
  QueryData results;

  // enumerate the base named objects in each terminal services session
  //
  std::vector<obj_name_type_pair> sessions;
  auto status = enumerateObjectNamespace(kBnoLinks, sessions);
  if (!status.ok()) {
    VLOG(1) << L"Unable to enumerate kBnoLinks: " << status.getCode();
    return results;
  }

  for (auto& session : sessions) {
    std::vector<obj_name_type_pair> objects;

    auto status =
        enumerateBaseNamedObjectsLinks(session.first, session.second, objects);

    for (auto& object : objects) {
      Row r;
      r["session_id"] = INTEGER(tryTo<int>(session.first).takeOr(0));
      r["object_name"] = wstringToString(object.first.c_str());
      r["object_type"] = wstringToString(object.second.c_str());

      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
