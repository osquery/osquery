/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include "Kobjhandle.h"
#include "ntapi.h"

#include <Windows.h>

namespace osquery {
namespace tables {

KObjHandle::KObjHandle() {
  _h = NULL;
}

KObjHandle::~KObjHandle() {
  close();
}

HANDLE KObjHandle::getAsHandle() {
  return _h;
}

bool KObjHandle::valid() {
  if (NULL != _h) {
    return true;
  }

  return false;
}

void KObjHandle::close() {
  if (NULL != _h) {
    CloseHandle(_h);
    _h = NULL;
  }
}

// open a Windows symbolic link by name with SYMBOLIC_LINK_QUERY
bool KObjHandle::openSymLinkObj(std::wstring strName) {
  if (valid()) {
    return false;
  }

  // look up address of NtOpenSymbolicLinkObject, exported from ntdll
  NTOPENSYMBOLICLINKOBJECT NtOpenSymbolicLinkObject =
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

  NTSTATUS ntStatus = NtOpenSymbolicLinkObject(&_h, SYMBOLIC_LINK_QUERY, &oa);
  if (STATUS_SUCCESS != ntStatus) {
    return false;
  }

  return true;
}

// open a Windows object directory object with DIRECTORY_QUERY
bool KObjHandle::openDirObj(std::wstring strName) {
  if (valid()) {
    return false;
  }

  // NtOpenDirectoryObject is documented on MSDN at
  // https://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
  NTOPENDIRECTORYOBJECT NtOpenDirectoryObject =
      (NTOPENDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtOpenDirectoryObject");
  if (NULL == NtOpenDirectoryObject) {
    return false;
  }

  // set up object attributes structure to describe the directory object
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
  NTSTATUS ntStatus = NtOpenDirectoryObject(&_h, DIRECTORY_QUERY, &oa);
  if (STATUS_SUCCESS != ntStatus) {
    return false;
  }

  return true;
}
} // tables
} // osquery
