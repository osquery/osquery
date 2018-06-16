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

#include "osquery/core/windows/ntapi.h"
#include "osquery/core/windows/handle.h"

namespace osquery {
namespace tables {

Handle::Handle() {
  _h = NULL;
}

Handle::~Handle() {
  close();
}

HANDLE Handle::getAsHandle() {
  return _h;
}

bool Handle::valid() {
  return (NULL != _h);
}

void Handle::close() {
  if (valid()) {
    CloseHandle(_h);
    _h = NULL;
  }
}

bool Handle::openSymLinkObj(const std::wstring& strName) {
  if (valid()) {
    return false;
  }

  // look up address of NtOpenSymbolicLinkObject, exported from ntdll
  //
  auto NtOpenSymbolicLinkObject =
      (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                               "NtOpenSymbolicLinkObject");
  if (NULL == NtOpenSymbolicLinkObject) {
    return false;
  }

  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING usLinkName;
  oa.Length = sizeof(oa);
  oa.RootDirectory = NULL;
  oa.ObjectName = &usLinkName;
  oa.ObjectName->Length = LOWORD(strName.length() * sizeof(WCHAR));
  oa.ObjectName->MaximumLength =
      LOWORD(strName.length() * sizeof(WCHAR) + sizeof(WCHAR));
  oa.ObjectName->Buffer = const_cast<PWCHAR>(strName.c_str());
  oa.Attributes = OBJ_CASE_INSENSITIVE;
  oa.SecurityDescriptor = NULL;
  oa.SecurityQualityOfService = NULL;

  auto ntStatus = NtOpenSymbolicLinkObject(&_h, SYMBOLIC_LINK_QUERY, &oa);
  if (STATUS_SUCCESS != ntStatus) {
    return false;
  }

  return true;
}

bool Handle::openDirObj(const std::wstring& strName) {
  if (valid()) {
    return false;
  }

  // NtOpenDirectoryObject is documented on MSDN at
  // https://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
  //
  auto NtOpenDirectoryObject =
      (NTOPENDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtOpenDirectoryObject");
  if (NULL == NtOpenDirectoryObject) {
    return false;
  }

  // set up object attributes structure to describe the directory object
  //
  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING us;
  oa.Length = sizeof(OBJECT_ATTRIBUTES);
  oa.RootDirectory = NULL;
  oa.ObjectName = &us;
  oa.ObjectName->Length = LOWORD(strName.length() * sizeof(WCHAR));
  oa.ObjectName->MaximumLength =
      LOWORD(strName.length() * sizeof(WCHAR) + sizeof(WCHAR));
  oa.ObjectName->Buffer = const_cast<PWCHAR>(strName.c_str());
  oa.Attributes = OBJ_CASE_INSENSITIVE;
  oa.SecurityDescriptor = NULL;
  oa.SecurityQualityOfService = NULL;

  // open the directory object
  // if successful, this returns STATUS_SUCCESS and populates _h with
  // a valid HANDLE to a kernel object
  auto ntStatus = NtOpenDirectoryObject(&_h, DIRECTORY_QUERY, &oa);
  if (STATUS_SUCCESS != ntStatus) {
    return false;
  }

  return true;
}
} // namespace tables
} // namespace osquery
