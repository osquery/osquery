/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>
#include <cstring>
#include <iostream>
#include <stdio.h>

#include <windows.h>
#include <psapi.h>
#include <tchar.h>

#include "osquery/core/windows/ntapi.h"
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>


namespace osquery {
namespace tables {

using obj_name_type_pair = std::pair<std::wstring, std::wstring>;

#define SystemHandleInformation 16
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define BUFF_SIZE 1000
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

BOOL getObjectName(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, UNICODE_STRING &objectName)
{
    PVOID   objectNameInfo;
    ULONG   returnLength;

    if ((objectNameInfo = malloc(0x1000)) == NULL)
    {
        return FALSE;
    }

	if (_NtQueryObject(processDupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength) != STATUS_SUCCESS)
    {
        // NtQuery failed, surement à cause du manque de buffer, donc on réaloue
        if ((objectNameInfo = realloc(objectNameInfo, returnLength)) == NULL)
        {
            free(objectNameInfo);
            return FALSE;
        }
        // On réessaye de récupérer le nom de l'objet
        if (_NtQueryObject(processDupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL) != STATUS_SUCCESS)
        {
            free(objectNameInfo);
            return FALSE;
        }
    }

    objectName = *(PUNICODE_STRING)objectNameInfo;
    free(objectNameInfo);
    return objectName.Length > 0;
}

BOOL getFilenameObject(HANDLE handle, std::wstring &filename)
{
    // Most of the code was taken from
    // https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
    void    *pMem;
    HANDLE  hFileMap;
    TCHAR   pszFilename[MAX_PATH + 1];
    DWORD   dwFileSizeHi = 0;
    DWORD   dwFileSizeLo = GetFileSize(&handle, &dwFileSizeHi); 

    if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
    {
        std::cout << "Cannot map a file with a length of zero." << std::endl;
        return FALSE;
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(handle, 
                    NULL,
                    PAGE_READONLY,
                    0, 
                    1,
                    NULL);
    if (!hFileMap)
        return FALSE;
    
    // Create a file mapping to get the file name.
    if (!(pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1)))
    {
        CloseHandle(hFileMap);
        return FALSE;
    }

    if (!GetMappedFileName(GetCurrentProcess(), 
        pMem, 
        pszFilename,
        MAX_PATH))
    {
        UnmapViewOfFile(pMem);
        CloseHandle(hFileMap);
        return FALSE;
    }
    // Translate path with device name to drive letters.
    TCHAR szTemp[BUFF_SIZE];
    szTemp[0] = '\0';

    if (GetLogicalDriveStrings(BUFF_SIZE - 1, szTemp)) 
    {
        TCHAR szName[MAX_PATH];
        TCHAR szDrive[3] = TEXT(" :");
        BOOL bFound = FALSE;
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

                    if (bFound) 
                    {
                        filename = szDrive;
                        filename.append(pszFilename + uNameLen);
                    }
                }
            }
            // Go to the next NULL character.
            while (*p++);
        } while (!bFound && *p); // end of string
    }
    else
    {
        filename = pszFilename;
    }
    UnmapViewOfFile(pMem);
    CloseHandle(hFileMap);
    return TRUE;
}

Status getHandleInfo(
    const HANDLE  &handle,
    const NtQueryObject &_NtQueryObject,
    Row &r)
{
    UNICODE_STRING objectName;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo;
    PVOID   objectNameInfo;
    ULONG   returnLength;

	if ((objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000)) == NULL){
        return Status(GetLastError(), "Could not allocate memory for objectTypeInfo");
    }


    r["object_type"] = wstringToString(objectTypeInfo->TypeName.Buffer);
    if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0 ) {
        // si c'est un fichier, on récupère le chemin complet
        std::wstring filename;
        if (getFilenameObject(handle, filename)) {
            r["object_name"] = "totoototoo";
        }
        
    }
    else if (getObjectName(_NtQueryObject, handle, objectName)) {
        // r["object_name"] = wstringToString(objectName.Buffer.c_str());
        if (_NtQueryObject(handle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) != STATUS_SUCCESS) {
            free(objectTypeInfo);
            return Status(GetLastError(), "Could not get object Type");
        }
        if (_NtQueryObject(handle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength) != STATUS_SUCCESS)
        {
            // NtQuery failed, surement à cause du manque de buffer, donc on réaloue
            if ((objectNameInfo = realloc(objectNameInfo, returnLength)) == NULL)
            {
                free(objectNameInfo);
                return Status(GetLastError(), "Could not realloc objectNameInfo");
            }
            // On réessaye de récupérer le nom de l'objet
            if (_NtQueryObject(handle, ObjectNameInformation, objectNameInfo, returnLength, NULL) != STATUS_SUCCESS)
            {
                free(objectNameInfo);
                return FALSE;
            }
        }
        objectName = *(PUNICODE_STRING)objectNameInfo;
        r["object_name"] = wstringToString(objectName.Buffer)


    }
    free(objectTypeInfo);

    return Status::success();
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

    // if ((ntdllModule = GetModuleHandleA("ntdll.dll")) == NULL) {
    //     VLOG(1) << L"Unable to get a handle on ntdll.dll";
    //     return rows;
    // }

    auto status = getSystemHandles(handleInfo);
    if (!status.ok()) {
        VLOG(1) << L"Unable to get system handles: " << status.getCode();
        return rows;
    }

    currentPid = GetCurrentProcessId();

    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        if (handleInfo->Handles[i].UniqueProcessId == currentPid) {
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
        Row r;
        // obj_name_type_pair objectPair;

        auto status = getHandleInfo(processDupHandle, _NtQueryObject, r);
        if (!status.ok()) {
            continue;
        }
        // if (objectPair.second.length() != 0 ) {
            r["pid"] = BIGINT(handleInfo->Handles[i].UniqueProcessId);
            rows.push_back(r);
        // }

    }

    return rows;
}

}
}