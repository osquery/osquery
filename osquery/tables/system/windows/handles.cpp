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


namespace osquery {
namespace tables {

typedef std::tuple<std::string, std::string> ObjectInfoTuple;

#define BUFF_SIZE 1000
#define IS_CONSOLE_HANDLE(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)
// this should probably be in osquery/core/windows/ntapi.h
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004


Status getObjectName(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, std::string &objectName)
{
    ULONG   returnLength;
    OBJECT_NAME_INFORMATION pName[BUFF_SIZE] = { 0 };

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
    LARGE_INTEGER    dwFileSizeHi = 0;
    DWORD   dwFileSizeLo = GetFileSizeEx(handle, &dwFileSizeHi); 

    if( dwFileSizeLo == 0 && dwFileSizeHi == 0 ) {
        return Status::failure("Cannot map a file with a length of zero: " + GetLastError());
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
    TCHAR szTemp[BUFF_SIZE];
    szTemp[0] = '\0';
    BOOL bFound = FALSE;

    if (GetLogicalDriveStrings(BUFF_SIZE - 1, szTemp)) 
    {
        TCHAR szName[MAX_PATH];
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
    return (_NtQueryObject(processDupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) == STATUS_SUCCESS);
}

Status getHandleInfo(
    const HANDLE  &handle,
    const NtQueryObject &_NtQueryObject,
    ObjectInfoTuple &objInfo)
{
    std::string objectName;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo;

    if ((objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000)) == NULL) {
        return Status::failure("Could not allocate memory for objectTypeInfo");
    }

    // Retrieve the object type
    if (!getObjectType(_NtQueryObject, handle, objectTypeInfo))
    {
        free(objectTypeInfo);
        return Status::failure("Could not get object type informations");
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

Status getSystemHandles(PSYSTEM_HANDLE_INFORMATION &handleInfo) {
    NTSTATUS ntstatus;
    ULONG handleInfoSize = 0x1000;

    auto _NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

    if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize)) == NULL){
        return Status(GetLastError(), "Could not allocate memory for handleInfo");
    }

    while ((ULONG)(ntstatus = _NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2)) == NULL){
            return Status(GetLastError(), "Could not re-allocate memory for for handleInfo");
        }
    }
    if (ntstatus != STATUS_SUCCESS ) {
        return Status(ntstatus, "Could not get system informations");
    }
    return Status::success();
}

QueryData genHandles(QueryContext &context) {
    QueryData rows;
    ULONG   i;
    DWORD   currentPid;
    HANDLE  processHandle;
    HANDLE  processDupHandle;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO  handle;

    // HMODULE ntdllModule;
    auto _NtDuplicateObject = reinterpret_cast<NtDuplicateObject>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"));
    auto _NtQueryObject = reinterpret_cast<NtQueryObject>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));

    auto status = getSystemHandles(handleInfo);
    if (!status.ok()) {
        VLOG(1) << L"Unable to get system handles: " << status.getCode();
        return rows;
    }

    currentPid = GetCurrentProcessId();

    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        if (handleInfo->Handles[i].UniqueProcessId == currentPid) {
            // Do not get handles for the current process
            continue;
        }
        handle = handleInfo->Handles[i];
        if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId))) {
            continue;
        }
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

        ObjectInfoTuple objInfo;
        auto status = getHandleInfo(processDupHandle, _NtQueryObject, objInfo);
        if (!status.ok()) {
            VLOG(1) << status.getMessage();
            continue;
        }
        // Build a row from the provided handle informations
        Row r;
        r["pid"] = BIGINT(handle.UniqueProcessId);
        r["object_type"] = std::get<0>(objInfo);
        r["object_name"] = std::get<1>(objInfo);
        rows.push_back(r);

    }

    return rows;
}

}
}