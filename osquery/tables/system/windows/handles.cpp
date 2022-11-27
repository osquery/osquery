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

#define SystemHandleInformation 16
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define BUFF_SIZE 1000
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define IS_CONSOLE_HANDLE(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)

typedef struct _OBJECT_NAME_INFORMATION
{
     UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

BOOL getObjectName(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, std::string &objectName)
{
    ULONG   returnLength;
    OBJECT_NAME_INFORMATION pName[BUFF_SIZE * 2] = { 0 };


    if (processDupHandle == 0 || processDupHandle == INVALID_HANDLE_VALUE){
        return FALSE;
    }
    // NtQueryObject returns STATUS_INVALID_HANDLE for Console handles
    if (IS_CONSOLE_HANDLE(processDupHandle))
    {
        std::stringstream sstream;
        sstream << "\\Device\\Console";
        sstream << std::hex << (DWORD)(DWORD_PTR)processDupHandle;
        objectName = sstream.str();
        return TRUE;
    }

	if (_NtQueryObject(processDupHandle, ObjectNameInformation, &pName, sizeof(pName), &returnLength) != 0){
        // TODO: Should probably realloc pName
        return FALSE;
    }

    if (!pName->Name.Length || !pName->Name.Buffer) {
        return FALSE;
    }
    objectName = wstringToString(pName->Name.Buffer);
    return TRUE;
}

BOOL getFilenameObject(HANDLE handle, std::string &filename)
{
    // source: https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
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
    if (!hFileMap) {
        return FALSE;
    }
    
    // Create a file mapping to get the file name.
    if (!(pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1))) {
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
    return TRUE;
}

BOOL getObjectType(const NtQueryObject &_NtQueryObject, const HANDLE &processDupHandle, PUBLIC_OBJECT_TYPE_INFORMATION *objectTypeInfo)
{
	return (_NtQueryObject(processDupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) == STATUS_SUCCESS);
}

BOOL getHandleInfo(
    const HANDLE  &handle,
    const NtQueryObject &_NtQueryObject,
    ObjectInfoTuple &objInfo)
{
    std::string objectName;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo;

	if ((objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000)) == NULL) {
		return FALSE;
    }

    // Récupération du type d'objet
    if (!getObjectType(_NtQueryObject, handle, objectTypeInfo))
    {
		free(objectTypeInfo);
		return FALSE;
    }
    std::get<0>(objInfo) = wstringToString(objectTypeInfo->TypeName.Buffer);
    if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0 )
    {
        // si c'est un fichier, on récupère le chemin complet
        std::string filename;

        if (getFilenameObject(handle, filename))
        {
            std::get<1>(objInfo) = filename;
            return TRUE;
            // std::cout << "file: "<<filename << std::endl;
        }
        
    }
    else if (getObjectName(_NtQueryObject, handle, objectName))
    {
        // std::cout << ">>>" << wstringToString(objectName.Buffer) << std::endl;
        std::get<1>(objInfo) = objectName;
        return TRUE;
        // std::wcout << "ELSE: " << objectName.Buffer << std::endl;
    }
    free(objectTypeInfo);

    return FALSE;
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
        // if (handleInfo->Handles[i].UniqueProcessId == currentPid) {
        //     continue;
        // }
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
        if (getHandleInfo(processDupHandle, _NtQueryObject, objInfo)) {
            std::cout << std::get<0>(objInfo) << " - " <<std::get<1>(objInfo) << std::endl;
        }
        // Row r;
        // ObjectInfoTuple objInfo;
        // if (getHandleInfo(processDupHandle, _NtQueryObject, objInfo)){
        //     std::cout << handle.UniqueProcessId << " > " << std::get<0>(objInfo) << " - " << std::get<1>(objInfo) << std::endl;   
        // }
 
        // if (objectPair.second.length() != 0 ) {
            // r["pid"] = BIGINT(handleInfo->Handles[i].UniqueProcessId);
            // rows.push_back(r);
        // }

    }

    return rows;
}

}
}