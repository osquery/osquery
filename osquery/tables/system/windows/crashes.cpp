// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/filesystem.hpp>
#include <Windows.h>
#pragma warning (push)
/*
C:\Program Files (x86)\Windows Kits\8.1\Include\um\DbgHelp.h(3190):
warning C4091: 'typedef ': ignored on left of '' when no variable is declared
*/
#pragma warning (disable:4091)
#include <DbgHelp.h>
#pragma warning (pop)
#pragma comment(lib, "dbghelp.lib")

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {
	const std::string kLocalDumpsRegKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
	const std::string kDumpFolderRegPath = kLocalDumpsRegKey + "\\DumpFolder";
	const std::string kDumpFileExtension = ".dmp";
	const std::string kFallbackFolder = "%TMP%";
	DWORD dwSysGran = NULL;

	Row extractDumpInfo(LPCTSTR lpFileName) {
		Row r;
		HANDLE hFile;
		HANDLE hMapFile;
		LPVOID pBase;

		// Open the file
		hFile = CreateFile(
			lpFileName,
			GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (hFile == NULL) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error opening crash dump file: " << lpFileName << " with error code " << dwError;
			return r;
		}

		// Create file mapping object
		hMapFile = CreateFileMapping(
			hFile,
			NULL,
			PAGE_READONLY,
			0,
			0,
			NULL
		);
		if (hMapFile == NULL) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error creating crash dump mapping object: " << lpFileName << " with error code " << dwError;
			CloseHandle(hFile);
			return r;
		}

		// Map the file
		if (dwSysGran == NULL) {
			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);
			dwSysGran = sysInfo.dwAllocationGranularity;
		}
		pBase = MapViewOfFile(
			hMapFile,
			FILE_MAP_READ,
			0,
			dwSysGran,
			0
		);
		if (pBase == NULL) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error mapping crash dump file: " << lpFileName << " with error code " << dwError;
			CloseHandle(hMapFile);
			CloseHandle(hFile);
			return r;
		}

		// Read dump file streams
		PMINIDUMP_DIRECTORY *pExceptionStreamDir = 0;
		PVOID *pExceptionStream = 0;
		ULONG *pExceptionStreamSize = 0;

		BOOL bDumpRead = MiniDumpReadDumpStream(
			pBase,
			ExceptionStream,
			pExceptionStreamDir,
			pExceptionStream,
			pExceptionStreamSize
		);
		if (!bDumpRead) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error reading crash dump file: " << lpFileName << " with error code " << dwError;
			UnmapViewOfFile(pBase);
			CloseHandle(hMapFile);
			CloseHandle(hFile);
			return r;
		}

		// TODO Extract info from streams
		r["test"] = lpFileName;	// if we see this in the table, minidump was read w/o errors

		// Cleanup
		UnmapViewOfFile(pBase);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return r;
	}

	QueryData genCrashLogs(QueryContext &context) {
		QueryData results;
		LPCTSTR szDumpFolderLocation;

		// Query registry for crash dump folder
		std::string dumpFolderQuery = "SELECT data FROM registry WHERE key = \"" + kLocalDumpsRegKey + "\" AND path = \"" + kDumpFolderRegPath + "\"";
		SQL dumpFolderResults(dumpFolderQuery);
		RowData dumpFolderRowData = dumpFolderResults.rows()[0].at("data");

		if (dumpFolderRowData.empty()) {
			LOG(WARNING) << "No crash dump folder found in registry; using fallback location of " << kFallbackFolder;
			szDumpFolderLocation = kFallbackFolder.c_str();
		}
		else {
			szDumpFolderLocation = dumpFolderRowData.c_str();
		}

		// Fill in any environment variables
		TCHAR szExpandedDumpFolderLocation[MAX_PATH];
		ExpandEnvironmentStrings(szDumpFolderLocation, szExpandedDumpFolderLocation, MAX_PATH);
		
		if (!boost::filesystem::exists(szExpandedDumpFolderLocation) ||
			!boost::filesystem::is_directory(szExpandedDumpFolderLocation)) {
			LOG(ERROR) << "Invalid crash dump directory: " << szExpandedDumpFolderLocation;
			return results;
		}

		// Enumerate and process crash dumps
		boost::filesystem::directory_iterator iterator(szExpandedDumpFolderLocation);
		boost::filesystem::directory_iterator endIterator;
		while (iterator != endIterator) {
			if (boost::filesystem::is_regular_file(*iterator) &&
				(iterator->path().extension() == kDumpFileExtension)) {
				Row r = extractDumpInfo(iterator->path().generic_string().c_str());
				if (!r.empty()) results.push_back(r);
			}
			++iterator;
		}

		return results;
	}
}
}