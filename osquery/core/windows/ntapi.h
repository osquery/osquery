/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/system.h>
#include <winternl.h>
namespace osquery {

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0L
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001L
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED 0xC0000022L
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL 0xC0000023L
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED 0xC00000BBL
#endif

#ifndef STATUS_INTEGER_OVERFLOW
#define STATUS_INTEGER_OVERFLOW 0xC0000095L
#endif

#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE 0xC0000008L
#endif

#ifndef STATUS_RETRY
#define STATUS_RETRY 0xC000022DL
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 64L
#endif

#define DIRECTORY_QUERY 0x0001
#define SYMBOLIC_LINK_QUERY 0x0001

// OBJECT_INFORMATION_CLASS is defined in winternl.h but is
// missing the following values
#ifndef ObjectNameInformation
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
#endif

#ifndef ObjectAllTypesInformation
#define ObjectAllTypesInformation ((OBJECT_INFORMATION_CLASS)3)
#endif

#ifndef ObjectHandleInformation
#define ObjectHandleInformation ((OBJECT_INFORMATION_CLASS)4)
#endif

// SystemExtendedHandleInformation is defined in winternl.h but is missing the
// following values
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation ((SYSTEM_INFORMATION_CLASS)64)
#endif

typedef NTSTATUS(WINAPI* ZwQueryObject)(HANDLE h,
                                        OBJECT_INFORMATION_CLASS oic,
                                        PVOID ObjectInformation,
                                        ULONG ObjectInformationLength,
                                        PULONG ReturnLength);

typedef NTSTATUS(WINAPI* ZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(WINAPI* NTCLOSE)(HANDLE Handle);

typedef NTSTATUS(WINAPI* NTOPENDIRECTORYOBJECT)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NTQUERYDIRECTORYOBJECT)(HANDLE DirectoryHandle,
                                                 PVOID Buffer,
                                                 ULONG Length,
                                                 BOOLEAN ReturnSingleEntry,
                                                 BOOLEAN RestartScan,
                                                 PULONG Context,
                                                 PULONG ReturnLength);

typedef NTSTATUS(WINAPI* NTOPENSYMBOLICLINKOBJECT)(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NTQUERYSYMBOLICLINKOBJECT)(HANDLE LinkHandle,
                                                    PUNICODE_STRING LinkTarget,
                                                    PULONG ReturnedLength);

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG ProcessId;
  BYTE ObjectTypeNumber;
  BYTE Flags;
  USHORT Handle;
  PVOID Object;
  ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJDIR_INFORMATION {
  UNICODE_STRING ObjectName;
  UNICODE_STRING ObjectTypeName;
  BYTE Data[1];
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

} // namespace osquery
