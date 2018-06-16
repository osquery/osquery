/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once


#include <windows.h>
namespace osquery {
namespace tables {

#define NTSTATUS ULONG
#define STATUS_SUCCESS 0L

#define OBJ_CASE_INSENSITIVE 64L
#define DIRECTORY_QUERY 0x0001
#define SYMBOLIC_LINK_QUERY 0x0001

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemPathInformation,
  SystemProcessInformation
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation,
  ObjectNameInformation,
  ObjectTypeInformation,
  ObjectAllTypesInformation,
  ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  PVOID RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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

} // namespace tables
} // namespace osquery