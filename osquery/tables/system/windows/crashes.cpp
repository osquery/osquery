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
	const std::string kFallbackFolder = "%TMP%";
	const std::string kDumpFileExtension = ".dmp";
	const std::map<ULONG64, std::string> kMiniDumpTypeFlags = {
		{ 0x00000000, "MiniDumpNormal" },
		{ 0x00000001, "MiniDumpWithDataSegs"},
		{ 0x00000002, "MiniDumpWithFullMemory" },
		{ 0x00000004, "MiniDumpWithHandleData" },
		{ 0x00000008, "MiniDumpFilterMemory" },
		{ 0x00000010, "MiniDumpScanMemory" },
		{ 0x00000020, "MiniDumpWithUnloadedModules" },
		{ 0x00000040, "MiniDumpWithIndirectlyReferencedMemory" },
		{ 0x00000080, "MiniDumpFilterModulePaths" },
		{ 0x00000100, "MiniDumpWithProcessThreadData" },
		{ 0x00000200, "MiniDumpWithPrivateReadWriteMemory" },
		{ 0x00000400, "MiniDumpWithoutOptionalData" },
		{ 0x00000800, "MiniDumpWithFullMemoryInfo" },
		{ 0x00001000, "MiniDumpWithThreadInfo" },
		{ 0x00002000, "MiniDumpWithCodeSegs" },
		{ 0x00004000, "MiniDumpWithoutAuxiliaryState" },
		{ 0x00008000, "MiniDumpWithFullAuxiliaryState" },
		{ 0x00010000, "MiniDumpWithPrivateWriteCopyMemory" },
		{ 0x00020000, "MiniDumpIgnoreInaccessibleMemory" },
		{ 0x00040000, "MiniDumpWithTokenInformation" },
		{ 0x00080000, "MiniDumpWithModuleHeaders" },
		{ 0x00100000, "MiniDumpFilterTriage" },
		{ 0x001fffff, "MiniDumpValidTypeFlags" }
	};
	const std::vector<MINIDUMP_STREAM_TYPE> streamTypes = { ThreadListStream, ModuleListStream, ExceptionStream, SystemInfoStream, MiscInfoStream };

	void processDumpExceptionStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize) {
		MINIDUMP_EXCEPTION_STREAM* pExceptionStream = (MINIDUMP_EXCEPTION_STREAM*)pDumpStream;
		MINIDUMP_EXCEPTION ex = pExceptionStream->ExceptionRecord;

		// Log message string for exception code
		switch (ex.ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			r["exception_type"] = "EXCEPTION_ACCESS_VIOLATION";
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			r["exception_type"] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
			break;
		case EXCEPTION_BREAKPOINT:
			r["exception_type"] = "EXCEPTION_BREAKPOINT";
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			r["exception_type"] = "EXCEPTION_DATATYPE_MISALIGNMENT";
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			r["exception_type"] = "EXCEPTION_FLT_DENORMAL_OPERAND";
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			r["exception_type"] = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			r["exception_type"] = "EXCEPTION_FLT_INEXACT_RESULT";
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			r["exception_type"] = "EXCEPTION_FLT_INVALID_OPERATION";
			break;
		case EXCEPTION_FLT_OVERFLOW:
			r["exception_type"] = "EXCEPTION_FLT_OVERFLOW";
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			r["exception_type"] = "EXCEPTION_FLT_STACK_CHECK";
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			r["exception_type"] = "EXCEPTION_FLT_UNDERFLOW";
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			r["exception_type"] = "EXCEPTION_ILLEGAL_INSTRUCTION";
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			r["exception_type"] = "EXCEPTION_IN_PAGE_ERROR";
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			r["exception_type"] = "EXCEPTION_INT_DIVIDE_BY_ZERO";
			break;
		case EXCEPTION_INT_OVERFLOW:
			r["exception_type"] = "EXCEPTION_INT_OVERFLOW";
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			r["exception_type"] = "EXCEPTION_INVALID_DISPOSITION";
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			r["exception_type"] = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			r["exception_type"] = "EXCEPTION_PRIV_INSTRUCTION";
			break;
		case EXCEPTION_SINGLE_STEP:
			r["exception_type"] = "EXCEPTION_SINGLE_STEP";
			break;
		case EXCEPTION_STACK_OVERFLOW:
			r["exception_type"] = "EXCEPTION_STACK_OVERFLOW";
			break;
		default:
			r["exception_type"] = "Unknown Exception";
			break;
		}

		// Log exception address
		std::stringstream exAddrAsHex;
		exAddrAsHex << std::hex << ex.ExceptionAddress;
		r["exception_address"] = exAddrAsHex.str();

		// Log the error code
		// Handle special cases for errors with parameters
		if ((ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) && (ex.NumberParameters == 2)) {
			std::stringstream errorCode;
			std::stringstream memAddrAsHex;
			memAddrAsHex << std::hex << ex.ExceptionInformation[1];

			errorCode << "The instruction at " << exAddrAsHex.str()
				<< " referenced memory at " << memAddrAsHex.str() << ". ";
			if (ex.ExceptionInformation[0] == 0) {
				errorCode << "The memory could not be read.";
			}
			else if (ex.ExceptionInformation[0] == 1) {
				errorCode << "The memory could not be written.";
			}
			r["exception_codes"] = errorCode.str();
		}
		// For errors without parameters, just log the NTSTATUS error code
		else {
			HMODULE hNTDLL = LoadLibrary("NTDLL.DLL");
			LPVOID lpNTSTATUS;
			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_FROM_HMODULE,
				hNTDLL,
				ex.ExceptionCode,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpNTSTATUS,
				0,
				NULL);
			r["exception_codes"] = (LPTSTR)lpNTSTATUS;
			LocalFree(lpNTSTATUS);
			FreeLibrary(hNTDLL);
		}

		// TODO process threadcontext

		return;
	}

	void processDumpMiscInfoStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize) {
		MINIDUMP_MISC_INFO* pMiscInfoStream = (MINIDUMP_MISC_INFO*)pDumpStream;

		// Log PID, if it exists
		if (pMiscInfoStream->Flags1 & MINIDUMP_MISC1_PROCESS_ID) {
			r["pid"] = BIGINT(pMiscInfoStream->ProcessId);
		}

		// Log process times, if they exist
		if (pMiscInfoStream->Flags1 & MINIDUMP_MISC1_PROCESS_TIMES) {
			r["process_create_time"] = BIGINT(pMiscInfoStream->ProcessCreateTime);
			r["process_user_time"] = BIGINT(pMiscInfoStream->ProcessUserTime);
			r["process_kernel_time"] = BIGINT(pMiscInfoStream->ProcessKernelTime);
		}

		return;
	}

	void processDumpSystemInfoStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize) {
		MINIDUMP_SYSTEM_INFO* pSystemInfoStream = (MINIDUMP_SYSTEM_INFO*)pDumpStream;

		// Log system version information
		r["major_version"] = INTEGER(pSystemInfoStream->MajorVersion);
		r["minor_version"] = INTEGER(pSystemInfoStream->MinorVersion);
		r["build_number"] = INTEGER(pSystemInfoStream->BuildNumber);

		return;
	}

	void processDumpModuleListStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize, LPVOID pBase) {
		MINIDUMP_MODULE_LIST *pModuleListStream = (MINIDUMP_MODULE_LIST*)pDumpStream;
		MINIDUMP_MODULE parentModule = pModuleListStream->Modules[0];

		// Log module path
		MINIDUMP_STRING* pModuleName = (MINIDUMP_STRING*)((BYTE*)pBase + parentModule.ModuleNameRva);
		char defChar = ' ';
		char ch[MAX_PATH];
		WideCharToMultiByte(CP_ACP, 0, pModuleName->Buffer, -1, ch, 260, &defChar, NULL);
		r["path"] = ch;

		// Log module version
		VS_FIXEDFILEINFO versionInfo = parentModule.VersionInfo;
		std::stringstream versionString;
		versionString << ((versionInfo.dwFileVersionMS >> 16) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionMS >> 0) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionLS >> 16) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionLS >> 0) & 0xffff);
		r["version"] = versionString.str();

		return;
	}

	void processDumpThreadListStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize) {
		MINIDUMP_THREAD_LIST *pThreadListStream = (MINIDUMP_THREAD_LIST*)pDumpStream;
		MINIDUMP_THREAD testThread = pThreadListStream->Threads[0];
		LOG(INFO) << "ThreadID: " << testThread.ThreadId;
		LOG(INFO) << "SuspendCount: " << testThread.SuspendCount;
		return;
	}

	void processDumpHeaderInfo(Row &r, PVOID pBase) {
		MINIDUMP_HEADER* pDumpHeader = (MINIDUMP_HEADER*)pBase;

		// Log dump timestamp
		time_t dumpTimestamp = pDumpHeader->TimeDateStamp;
		struct tm gmt;
		char timeBuff[64];
		gmtime_s(&gmt, &dumpTimestamp);
		strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);
		r["datetime"] = timeBuff;

		// Log dump type
		std::stringstream activeFlags;
		bool firstString = true;
		for (auto const& flag : kMiniDumpTypeFlags) {
			// If this MINIDUMP_TYPE flag is set, log it
			if (pDumpHeader->Flags & flag.first) {
				if (!firstString) activeFlags << ",";
				firstString = false;
				activeFlags << flag.second;
			}
		}
		r["type"] = activeFlags.str();

		return;
	}

	Row extractDumpInfo(LPCTSTR lpFileName) {
		Row r;
		HANDLE hFile;
		HANDLE hMapFile;
		LPVOID pBase;

		r["crash_path"] = lpFileName;

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
		pBase = MapViewOfFile(
			hMapFile,
			FILE_MAP_READ,
			0,
			0,
			0
		);
		if (pBase == NULL) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error mapping crash dump file: " << lpFileName << " with error code " << dwError;
			CloseHandle(hMapFile);
			CloseHandle(hFile);
			return r;
		}
		
		// Process dump header info
		processDumpHeaderInfo(r, pBase);

		// Process dump file info from each stream
		for (auto stream : streamTypes) {
			PMINIDUMP_DIRECTORY pDumpStreamDir = 0;
			PVOID pDumpStream = 0;
			ULONG pDumpStreamSize = 0;

			BOOL bDumpRead = MiniDumpReadDumpStream(
				pBase,
				stream,
				&pDumpStreamDir,
				&pDumpStream,
				&pDumpStreamSize
			);
			if (!bDumpRead) {
				DWORD dwError = GetLastError();
				LOG(ERROR) << "Error reading stream " << stream << " in crash dump file: " << lpFileName << " with error code " << dwError;
				continue;
			}

			switch (stream) {
			case ThreadListStream:
				processDumpThreadListStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize);
				break;
			case ModuleListStream:
				processDumpModuleListStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize, pBase);
				break;
			case ExceptionStream:
				processDumpExceptionStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize);
				break;
			case SystemInfoStream:
				processDumpSystemInfoStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize);
				break;
			case MiscInfoStream:
				processDumpMiscInfoStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize);
				break;
			default:
				LOG(ERROR) << "Attempting to process unsupported crash dump stream: " << stream;
				break;
			}
		}

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

		if (dumpFolderResults.rows().empty()) {
			LOG(WARNING) << "No crash dump folder found in registry; using fallback location of " << kFallbackFolder;
			szDumpFolderLocation = kFallbackFolder.c_str();
		}
		else {
			RowData dumpFolderRowData = dumpFolderResults.rows()[0].at("data");
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
			std::string sExtension = iterator->path().extension().string();
			std::transform(sExtension.begin(), sExtension.end(), sExtension.begin(), ::tolower);
			if (boost::filesystem::is_regular_file(*iterator) &&
				(sExtension.compare(kDumpFileExtension) == 0)) {
				Row r = extractDumpInfo(iterator->path().generic_string().c_str());
				if (!r.empty()) results.push_back(r);
			}
			++iterator;
		}

		return results;
	}
}
}