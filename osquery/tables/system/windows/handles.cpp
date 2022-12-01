/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstring>
#include <sstream>

#include <windows.h>
#include <psapi.h>
#include <tchar.h>

#include "osquery/core/windows/ntapi.h"
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>


namespace osquery {
namespace tables {

#define IS_CONSOLE_HANDLE(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

using ObjectInfoTuple = std::tuple<std::string, std::string>;

const DWORD BUFF_SIZE = 0x1000;


Status getObjectName(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, std::string &objectName)
{
    ULONG   returnLength;
    OBJECT_NAME_INFORMATION pName[BUFF_SIZE * 2] = { 0 };

    if (processDupHandle == 0 || processDupHandle == INVALID_HANDLE_VALUE){
        return Status::failure("Invalid handle");
    }
    // NtQueryObject returns STATUS_INVALID_HANDLE for Console handles
    if (IS_CONSOLE_HANDLE(processDupHandle))
    {
        std::stringstream sstream;
        sstream << "\\Device\\Console";
        sstream << std::hex << (DWORD)(DWORD_PTR)processDupHandle;
        objectName = sstream.str();
        return Status::success();
    }
    
    if (_NtQueryObject(processDupHandle, ObjectNameInformation, &pName, sizeof(pName), &returnLength) != STATUS_SUCCESS){
        // TODO: Should probably realloc pName
        return Status::failure("Could not get object name informations");
    }

    if (!pName->Name.Length || !pName->Name.Buffer) {
        return Status::failure("Object name is empty");
    }
    objectName = wstringToString(pName->Name.Buffer);
    return Status::success();
}

// Code adapted from: https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
Status getFilenameObject(HANDLE handle, std::string &filename)
{
    void    *pMem;
    HANDLE  hFileMap;
    TCHAR   pszFilename[MAX_PATH + 1];
    DWORD   dwFileSizeHi = 0;
    DWORD   dwFileSizeLo = GetFileSize(&handle, &dwFileSizeHi); 
    TCHAR   szTemp[BUFF_SIZE];
    BOOL    bFound = FALSE;
    TCHAR   szName[MAX_PATH];

    if( dwFileSizeLo == 0 && dwFileSizeHi == 0 ) {
        return Status::failure("Cannot map a file with a length of zero.");
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(handle, 
                    NULL,
                    PAGE_READONLY,
                    0, 
                    1,
                    NULL);
    if (!hFileMap) {
        return Status::failure("Error while trying to map file.");
    }
    
    // Create a file mapping to get the file name.
    if (!(pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1)))
    {
        CloseHandle(hFileMap);
        return Status::failure("Error while trying to map a view of the file.");
    }

    if (!GetMappedFileName(GetCurrentProcess(), 
        pMem,
        pszFilename,
        MAX_PATH))
    {
        UnmapViewOfFile(pMem);
        CloseHandle(hFileMap);
        return Status::failure("Error while trying to get mapped filename.");
    }

    // Translate path with device name to drive letters.
    szTemp[0] = '\0';

    if (GetLogicalDriveStrings(BUFF_SIZE - 1, szTemp)) 
    {
        TCHAR szDrive[3] = TEXT(" :");
        TCHAR *p = szTemp;
        do 
        {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDevice(szDrive, szName, MAX_PATH))
            {
                size_t uNameLen = _tcslen(szName);

                if (uNameLen < MAX_PATH) 
                {
                    bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                        && *(pszFilename + uNameLen) == _T('\\');

                    if (bFound) {
                        filename = wstringToString(szDrive) + wstringToString(pszFilename + uNameLen);
                    }
                }
            }
            // Go to the next NULL character.
            while (*p++);
        } while (!bFound && *p); // end of string
    }
    if (!bFound) {
        // Could not find drive name, so we set the full file path
        filename = wstringToString(pszFilename);
    }
    UnmapViewOfFile(pMem);
    CloseHandle(hFileMap);
    return Status::success();
}

BOOL getObjectType(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, PUBLIC_OBJECT_TYPE_INFORMATION *objectTypeInfo)
{
    return (_NtQueryObject(processDupHandle, ObjectTypeInformation, objectTypeInfo, BUFF_SIZE, NULL) == STATUS_SUCCESS);
}

Status getHandleInfo(
    const HANDLE  &handle,
    const NtQueryObject &_NtQueryObject,
    ObjectInfoTuple &objInfo)
{
    std::string objectName;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo;

    if ((objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(BUFF_SIZE)) == NULL) {
        return Status::failure("Could not allocate memory for objectTypeInfo");
    }

    // Retrieve the object type
    if (!getObjectType(_NtQueryObject, handle, objectTypeInfo))
    {
        free(objectTypeInfo);
        return Status::failure("Could not get object type information");
    }
    std::get<0>(objInfo) = wstringToString(objectTypeInfo->TypeName.Buffer);

    // If it's a file, try to retrieve the human readable path name
    // Otherwise, dumps the object name
    if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0 )
    {
        std::string filename;
        auto status = getFilenameObject(handle, filename);
        if (status.ok())
        {
            std::get<1>(objInfo) = filename;
            return Status::success();
        }
        
    }
    else if (getObjectName(_NtQueryObject, handle, objectName))
    {
        std::get<1>(objInfo) = objectName;
        return Status::success();
    }
    free(objectTypeInfo);

    return Status::failure("Could not get object name for " + std::get<0>(objInfo));
}

Status getSystemHandles(PSYSTEM_HANDLE_INFORMATION_EX &handleInfo) {
    NTSTATUS ntstatus;
    HMODULE ntdllModule = nullptr;
    DWORD initialAllocationBuffer = 0x1000;

    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,"ntdll.dll", &ntdllModule);
    auto _NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(GetProcAddress(ntdllModule, "NtQuerySystemInformation"));

    if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(initialAllocationBuffer)) == NULL){
        return Status(GetLastError(), "Could not allocate memory for handleInfo");
    }

	while ((ULONG)(ntstatus = _NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, initialAllocationBuffer, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, initialAllocationBuffer *= 2)) == NULL){
            return Status(GetLastError(), "Could not re-allocate memory for for handleInfo");
        }
    }
    if (ntstatus != STATUS_SUCCESS ) {
        return Status(ntstatus, "Could not get system informations");
    }
    return Status::success();
}

std::string getHandleAttributes(const ULONG &handleAttributes) {

    std::stringstream ss;

    if ((handleAttributes & OBJ_INHERIT) == OBJ_INHERIT) {
        ss << "OBJ_INHERIT";
    }
    if ((handleAttributes & OBJ_PERMANENT) == OBJ_PERMANENT) {
        ss << ",OBJ_PERMANENT";
    }
    if ((handleAttributes & OBJ_EXCLUSIVE) == OBJ_EXCLUSIVE) {
        ss << ",OBJ_EXCLUSIVE";
    }
    if ((handleAttributes & OBJ_CASE_INSENSITIVE) == OBJ_CASE_INSENSITIVE) {
        ss << ",OBJ_CASE_INSENSITIVE";
    }
    if ((handleAttributes & OBJ_OPENIF) == OBJ_OPENIF) {
        ss << ",OBJ_OPENIF";
    }
    if ((handleAttributes & OBJ_OPENLINK) == OBJ_OPENLINK) {
        ss << ",OBJ_OPENLINK";
    }
    if ((handleAttributes & OBJ_KERNEL_HANDLE) == OBJ_KERNEL_HANDLE) {
        ss << ",OBJ_KERNEL_HANDLE";
    }
    if ((handleAttributes & OBJ_FORCE_ACCESS_CHECK) == OBJ_FORCE_ACCESS_CHECK) {
        ss << ",OBJ_FORCE_ACCESS_CHECK";
    }
    if ((handleAttributes & OBJ_IGNORE_IMPERSONATED_DEVICEMAP) == OBJ_IGNORE_IMPERSONATED_DEVICEMAP) {
        ss << ",OBJ_IGNORE_IMPERSONATED_DEVICEMAP";
    }
    if ((handleAttributes & OBJ_DONT_REPARSE) == OBJ_DONT_REPARSE) {
        ss << ",OBJ_DONT_REPARSE";
    }
    if ((handleAttributes & OBJ_VALID_ATTRIBUTES) == OBJ_VALID_ATTRIBUTES) {
        ss << ",OBJ_VALID_ATTRIBUTES";
    }

    std::string handlesAttrsString = ss.str();
    if (!handlesAttrsString.empty() && handlesAttrsString.front() == ',') {
        handlesAttrsString.erase(handlesAttrsString.begin());
    }
    return handlesAttrsString;
}

QueryData genHandles(QueryContext &context) {
    QueryData rows;
    ULONG   i;
    // DWORD   currentPid;
    HANDLE  processHandle;
    HANDLE  processDupHandle;
    PSYSTEM_HANDLE_INFORMATION_EX   handleInfo;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX   handle;
    HMODULE ntdllModule = nullptr;

    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,"ntdll.dll", &ntdllModule);
    auto _NtDuplicateObject = reinterpret_cast<NtDuplicateObject>(GetProcAddress(ntdllModule, "NtDuplicateObject"));
    auto _NtQueryObject = reinterpret_cast<NtQueryObject>(GetProcAddress(ntdllModule, "NtQueryObject"));

    auto status = getSystemHandles(handleInfo);
    auto const guard_process_dup_handle = scope_guard::create([processDupHandle]() { CloseHandle(processDupHandle); });

    if (!status.ok()) {
        VLOG(1) << L"Unable to get system handles: " << status.getCode();
        return rows;
    }

    // currentPid = GetCurrentProcessId();
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        // if (handleInfo->Handles[i].UniqueProcessId == currentPid) {
        //     // Do not get handles for the current process
        //     continue;
        // }
        handle = handleInfo->Handles[i];
        // std::cout << handle.UniqueProcessId << std::endl;
	    processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)handle.UniqueProcessId);
	    if (!processHandle) {
            continue;
        }
        auto const guard_process_handle = scope_guard::create([&processHandle]() { CloseHandle(processHandle); });

        if (_NtDuplicateObject(
            processHandle,
            (HANDLE)(intptr_t)handle.HandleValue,
            GetCurrentProcess(),
            &processDupHandle,
            GENERIC_READ,
            0,
            0) != STATUS_SUCCESS)
        {
            CloseHandle(processHandle);
            CloseHandle(processDupHandle);
            continue;
        }
        auto const guard_process_dup_handle = scope_guard::create([processDupHandle]() { CloseHandle(processDupHandle); });

        ObjectInfoTuple objInfo;
        auto status_hinfo = getHandleInfo(processDupHandle, _NtQueryObject, objInfo);
        if (!status_hinfo.ok()) {
            VLOG(1) << status_hinfo.getMessage();
            continue;
        }
        // Build a row from the provided handle informations
        auto handle_attributes = getHandleAttributes(handle.GrantedAccess);
        Row r;
        // std::cout << handle.GrantedAccess & 0x00000002 << std::endl;
        // std::cout << handle.GrantedAccess & 0x00000004 << std::endl;
        // std::cout << handle.GrantedAccess & 0x00000010 << std::endl;
        // std::cout << handle.GrantedAccess & 0x00000020 << std::endl;
        // std::cout << handle.GrantedAccess & 0x00000040 << std::endl;
        // std::cout << handle.GrantedAccess & 0x00000800 << std::endl;
        // std::cout << "=>" <<handle.HandleAttributes << std::endl;

        r["pid"] = BIGINT(handle.UniqueProcessId);
        r["object_type"] = std::get<0>(objInfo);
        r["object_name"] = std::get<1>(objInfo);
        r["attributes"] = handle_attributes;
        rows.push_back(r);

    }

    return rows;
}

}
}