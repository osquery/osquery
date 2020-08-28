/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <osquery/core/windows/handle.h>
#include <osquery/core/windows/ntapi.h>

namespace osquery {

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

Status Handle::openSymLinkObj(const std::wstring& strName) {
  if (valid()) {
    return Status(ERROR_ALREADY_ASSIGNED, "Handle object already open");
  }

  // look up address of NtOpenSymbolicLinkObject, exported from ntdll
  //
  auto NtOpenSymbolicLinkObject = reinterpret_cast<NTOPENSYMBOLICLINKOBJECT>(
      GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenSymbolicLinkObject"));
  if (nullptr == NtOpenSymbolicLinkObject) {
    return Status(GetLastError(), "Unable to find NtOpenSymbolicLinkObject");
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
    return Status(ntStatus, "NtOpenSymbolicLinkObject returned failure");
  }

  return Status::success();
}

Status Handle::openDirObj(const std::wstring& strName) {
  if (valid()) {
    return Status(ERROR_ALREADY_ASSIGNED, "Handle object already open");
  }

  // NtOpenDirectoryObject is documented on MSDN at
  // https://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
  //
  auto NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtOpenDirectoryObject");
  if (nullptr == NtOpenDirectoryObject) {
    return Status(GetLastError(), "Unable to find NtOpenDirectoryObject");
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
    return Status(ntStatus, "NtOpenDirecotryObject returned failure");
  }

  return Status::success();
}
} // namespace osquery
