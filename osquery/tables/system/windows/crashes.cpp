// Copyright 2004-present Facebook. All Rights Reserved.

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winternl.h>
#pragma warning (push)
/*
C:\Program Files (x86)\Windows Kits\8.1\Include\um\DbgHelp.h(3190):
warning C4091: 'typedef ': ignored on left of '' when no variable is declared
*/
#pragma warning (disable:4091)
#include <DbgHelp.h>
#pragma warning (pop)
#pragma comment(lib, "dbghelp.lib")
#include <DbgEng.h>
#pragma comment(lib ,"dbgeng.lib")

#include <boost/filesystem.hpp>

#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

	const std::string kLocalDumpsRegKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
	const std::string kDumpFolderRegPath = kLocalDumpsRegKey + "\\DumpFolder";
	const std::string kFallbackFolder = "%TMP%";
	const std::string kDumpFileExtension = ".dmp";
	const ULONG kulNumStackFramesToLog = 10;
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
	// Note: ModuleListStream should be processed after ExceptionStream so the exception addr is defined
	// ThreadListStream should be processed after ExceptionStream so the crashed thread is defined
	// MemoryListStream should be processed after ThreadListStream so the PEB address is defined
	const std::vector<MINIDUMP_STREAM_TYPE> kStreamTypes = { ExceptionStream, ModuleListStream, ThreadListStream, MemoryListStream, SystemInfoStream, MiscInfoStream };

	ULONG64 ulExceptionAddress = NULL;
	ULONG32 ulTID = NULL;
	ULONG64 ulTEBAddress = NULL;
	ULONG64 ulMiniDumpFlags = NULL;

	void processDumpExceptionStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize, PVOID pBase) {
		MINIDUMP_EXCEPTION_STREAM* pExceptionStream = (MINIDUMP_EXCEPTION_STREAM*)pDumpStream;
		MINIDUMP_EXCEPTION ex = pExceptionStream->ExceptionRecord;

		// Log ID of thread that caused the exception
		r["tid"] = BIGINT(pExceptionStream->ThreadId);
		ulTID = pExceptionStream->ThreadId;

		// Log exception code
		std::stringstream exCode;
		// Note: easiest to hard-code cases b/c C++ has no reflection
		switch (ex.ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			exCode << "EXCEPTION_ACCESS_VIOLATION ";
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			exCode << "EXCEPTION_ARRAY_BOUNDS_EXCEEDED ";
			break;
		case EXCEPTION_BREAKPOINT:
			exCode << "EXCEPTION_BREAKPOINT ";
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			exCode << "EXCEPTION_DATATYPE_MISALIGNMENT ";
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			exCode << "EXCEPTION_FLT_DENORMAL_OPERAND ";
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			exCode << "EXCEPTION_FLT_DIVIDE_BY_ZERO ";
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			exCode << "EXCEPTION_FLT_INEXACT_RESULT ";
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			exCode << "EXCEPTION_FLT_INVALID_OPERATION ";
			break;
		case EXCEPTION_FLT_OVERFLOW:
			exCode << "EXCEPTION_FLT_OVERFLOW ";
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			exCode << "EXCEPTION_FLT_STACK_CHECK ";
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			exCode << "EXCEPTION_FLT_UNDERFLOW ";
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			exCode << "EXCEPTION_ILLEGAL_INSTRUCTION ";
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			exCode << "EXCEPTION_IN_PAGE_ERROR ";
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			exCode << "EXCEPTION_INT_DIVIDE_BY_ZERO ";
			break;
		case EXCEPTION_INT_OVERFLOW:
			exCode << "EXCEPTION_INT_OVERFLOW ";
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			exCode << "EXCEPTION_INVALID_DISPOSITION ";
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			exCode << "EXCEPTION_NONCONTINUABLE_EXCEPTION ";
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			exCode << "EXCEPTION_PRIV_INSTRUCTION ";
			break;
		case EXCEPTION_SINGLE_STEP:
			exCode << "EXCEPTION_SINGLE_STEP ";
			break;
		case EXCEPTION_STACK_OVERFLOW:
			exCode << "EXCEPTION_STACK_OVERFLOW ";
			break;
		default:
			break;
		}
		exCode << "(" << std::hex << ex.ExceptionCode;
		exCode << ")";
		r["exception_code"] = exCode.str();

		// Log exception address
		std::stringstream exAddrAsHex;
		exAddrAsHex << std::hex << ex.ExceptionAddress;
		r["exception_address"] = exAddrAsHex.str();
		ulExceptionAddress = ex.ExceptionAddress;

		// Log the exception message for errors with defined parameters
		// (see ExceptionInformation @ https://msdn.microsoft.com/en-us/library/windows/desktop/ms680367(v=vs.85).aspx)
		if ((ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) && (ex.NumberParameters == 2)) {
			std::stringstream errorMsg;
			std::stringstream memAddrAsHex;
			memAddrAsHex << std::hex << ex.ExceptionInformation[1];

			errorMsg << "The instruction at " << exAddrAsHex.str()
				<< " referenced memory at " << memAddrAsHex.str() << ".";
			switch (ex.ExceptionInformation[0]) {
			case 0:
				errorMsg << " The memory could not be read.";
				break;
			case 1:
				errorMsg << " The memory could not be written.";
				break;
			case 8:
				errorMsg << " DEP access violation.";
				break;
			}

			r["exception_message"] = errorMsg.str();
		}

		// Log registers from crashed thread
		CONTEXT* pThreadContext = (CONTEXT*)((BYTE*)pBase + pExceptionStream->ThreadContext.Rva);
		std::stringstream registers;
		// Registers are hard-coded for x64 system b/c lack of C++ reflection on CONTEXT object
		registers << "rax:" << std::hex << pThreadContext->Rax;
		registers << " rbx:" << std::hex << pThreadContext->Rbx;
		registers << " rcx:" << std::hex << pThreadContext->Rcx;
		registers << " rdx:" << std::hex << pThreadContext->Rdx;
		registers << " rdi:" << std::hex << pThreadContext->Rdi;
		registers << " rsi:" << std::hex << pThreadContext->Rsi;
		registers << " rbp:" << std::hex << pThreadContext->Rbp;
		registers << " rsp:" << std::hex << pThreadContext->Rsp;
		registers << " r8:" << std::hex << pThreadContext->R8;
		registers << " r9:" << std::hex << pThreadContext->R9;
		registers << " r10:" << std::hex << pThreadContext->R10;
		registers << " r11:" << std::hex << pThreadContext->R11;
		registers << " r12:" << std::hex << pThreadContext->R12;
		registers << " r13:" << std::hex << pThreadContext->R13;
		registers << " r14:" << std::hex << pThreadContext->R14;
		registers << " r15:" << std::hex << pThreadContext->R15;
		registers << " rip:" << std::hex << pThreadContext->Rip;
		registers << " segcs:" << std::hex << pThreadContext->SegCs;
		registers << " segds:" << std::hex << pThreadContext->SegDs;
		registers << " seges:" << std::hex << pThreadContext->SegEs;
		registers << " segfs:" << std::hex << pThreadContext->SegFs;
		registers << " seggs:" << std::hex << pThreadContext->SegGs;
		registers << " segss:" << std::hex << pThreadContext->SegSs;
		registers << " eflags:" << std::hex << pThreadContext->EFlags;
		r["registers"] = registers.str();

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
			time_t procTimestamp = pMiscInfoStream->ProcessCreateTime;
			struct tm gmt;
			char timeBuff[64];
			gmtime_s(&gmt, &procTimestamp);
			strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);
			r["process_create_time"] = timeBuff;
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

		// Log PE path
		MINIDUMP_MODULE exeModule = pModuleListStream->Modules[0];
		MINIDUMP_STRING* pExePath = (MINIDUMP_STRING*)((BYTE*)pBase + exeModule.ModuleNameRva);
		r["path"] = wstringToString(pExePath->Buffer);

		// Log PE version
		VS_FIXEDFILEINFO versionInfo = exeModule.VersionInfo;
		std::stringstream versionString;
		versionString << ((versionInfo.dwFileVersionMS >> 16) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionMS >> 0) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionLS >> 16) & 0xffff) << "."
			<< ((versionInfo.dwFileVersionLS >> 0) & 0xffff);
		r["version"] = versionString.str();

		// Log module that caused the exception, if any
		if (ulExceptionAddress != NULL) {
			for (ULONG32 i = 0; i < pModuleListStream->NumberOfModules; i++) {
				MINIDUMP_MODULE module = pModuleListStream->Modules[i];
				// Is the exception address within this module's memory space?
				if ((module.BaseOfImage <= ulExceptionAddress) && (ulExceptionAddress <= (module.BaseOfImage+module.SizeOfImage))) {
					MINIDUMP_STRING* pModulePath = (MINIDUMP_STRING*)((BYTE*)pBase + module.ModuleNameRva);
					r["module"] = wstringToString(pModulePath->Buffer);
					break;
				}
			}
		}

		return;
	}

	void processDumpThreadListStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize) {
		MINIDUMP_THREAD_LIST *pThreadListStream = (MINIDUMP_THREAD_LIST*)pDumpStream;

		// Fetch TEB address of crashed thread for later processing
		if (ulTID != NULL) {
			for (ULONG32 i = 0; i < pThreadListStream->NumberOfThreads; i++) {
				MINIDUMP_THREAD thread = pThreadListStream->Threads[i];
				if (thread.ThreadId == ulTID) {
					ulTEBAddress = thread.Teb;
					break;
				}
			}
		}

		return;
	}

	MINIDUMP_MEMORY_DESCRIPTOR* getMemRangeContainingTarget(ULONG64 ulTarget, MINIDUMP_MEMORY_LIST *pMemoryListStream) {
		for (ULONG32 i = 0; i < pMemoryListStream->NumberOfMemoryRanges; i++) {
			MINIDUMP_MEMORY_DESCRIPTOR memRange = pMemoryListStream->MemoryRanges[i];
			if ((memRange.StartOfMemoryRange <= ulTarget) &&
				(ulTarget < (memRange.StartOfMemoryRange + memRange.Memory.DataSize))) {
				return &pMemoryListStream->MemoryRanges[i];
			}
		}
		return nullptr;
	}

	void processMemoryListStream(Row &r, PMINIDUMP_DIRECTORY pDumpStreamDir, PVOID pDumpStream, ULONG pDumpStreamSize, LPVOID pBase, LPCTSTR lpFileName) {
		MINIDUMP_MEMORY_LIST *pMemoryListStream = (MINIDUMP_MEMORY_LIST*)pDumpStream;
		
		// Log PEB data
		if ((ulTEBAddress != NULL) && (ulMiniDumpFlags & MiniDumpWithProcessThreadData)) {
			// Get TEB from Minidump memory
			MINIDUMP_MEMORY_DESCRIPTOR *pMemTEB = getMemRangeContainingTarget(ulTEBAddress, pMemoryListStream);
			if (pMemTEB != nullptr) {
				ULONG64 ulTEBOffset = ulTEBAddress - pMemTEB->StartOfMemoryRange;
				TEB* pTEB = (TEB*)((BYTE*)pBase + pMemTEB->Memory.Rva + ulTEBOffset);

				// Get PEB from Minidump memory
				ULONG64 ulPEBAddress = (ULONG64)pTEB->ProcessEnvironmentBlock;
				MINIDUMP_MEMORY_DESCRIPTOR *pMemPEB = getMemRangeContainingTarget(ulPEBAddress, pMemoryListStream);
				if (pMemPEB != nullptr) {
					ULONG64 ulPEBOffset = ulPEBAddress - pMemPEB->StartOfMemoryRange;
					PEB* pPEB = (PEB*)((BYTE*)pBase + pMemPEB->Memory.Rva + ulPEBOffset);

					// Log BeingDebugged
					if (pPEB->BeingDebugged == TRUE) {
						r["being_debugged"] = "true";
					}
					else {
						r["being_debugged"] = "false";
					}

					// Get process parameters from Minidump memory
					ULONG64 ulParamsAddress = (ULONG64)pPEB->ProcessParameters;
					MINIDUMP_MEMORY_DESCRIPTOR *pMemParams = getMemRangeContainingTarget(ulParamsAddress, pMemoryListStream);
					if (pMemParams != nullptr) {
						ULONG64 ulParamsOffset = ulParamsAddress - pMemParams->StartOfMemoryRange;
						RTL_USER_PROCESS_PARAMETERS* params = (RTL_USER_PROCESS_PARAMETERS*)((BYTE*)pBase + pMemParams->Memory.Rva + ulParamsOffset);

						// Get command line arguments from Minidump memory
						ULONG64 ulBufferAddress = (ULONG64)params->CommandLine.Buffer;
						MINIDUMP_MEMORY_DESCRIPTOR *pMemBuffer = getMemRangeContainingTarget(ulBufferAddress, pMemoryListStream);
						if (pMemBuffer != nullptr) {
							ULONG64 ulBufferOffset = ulBufferAddress - pMemBuffer->StartOfMemoryRange;
							PWSTR buffer = (PWSTR)((BYTE*)pBase + pMemBuffer->Memory.Rva + ulBufferOffset);
							r["command_line"] = wstringToString(buffer);
						}

						// Get environment variables from Minidump memory

						// Get current directory from Minidump memory
					}
				}
				else {
					LOG(ERROR) << "Error reading PEB for crash dump: " << lpFileName;
				}
			}
		}

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
		// Loop through MINIDUMP_TYPE flags and log the ones that are set
		for (auto const& flag : kMiniDumpTypeFlags) {
			if (pDumpHeader->Flags & flag.first) {
				if (!firstString) activeFlags << ",";
				firstString = false;
				activeFlags << flag.second;
			}
		}
		r["type"] = activeFlags.str();
		ulMiniDumpFlags = pDumpHeader->Flags;

		return;
	}

	void extractDumpInfo(Row &r, LPCTSTR lpFileName) {
		HANDLE hFile;
		HANDLE hMapFile;
		LPVOID pBase;

		r["crash_path"] = lpFileName;

		// Open the file
		hFile = CreateFile(
			lpFileName,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (hFile == NULL) {
			DWORD dwError = GetLastError();
			LOG(ERROR) << "Error opening crash dump file: " << lpFileName << " with error code " << dwError;
			return;
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
			return;
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
			return;
		}
		
		// Process dump header info
		processDumpHeaderInfo(r, pBase);

		// Process dump file info from each stream
		for (auto stream : kStreamTypes) {
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
			case MemoryListStream:
				processMemoryListStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize, pBase, lpFileName);
				break;
			case ExceptionStream:
				processDumpExceptionStream(r, pDumpStreamDir, pDumpStream, pDumpStreamSize, pBase);
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
		return;
	}

	void debugEngineCleanup(IDebugClient4* client, IDebugControl4* control, IDebugSymbols3* symbols) {
		if (symbols != NULL) symbols->Release();
		if (control != NULL) control->Release();
		if (client != NULL) {
			client->SetOutputCallbacks(NULL);
			client->EndSession(DEBUG_END_PASSIVE);
			client->Release();
		}
		return;
	}

	// Note: appears to only detect unmanaged stack frames.
	// See http://blog.steveniemitz.com/building-a-mixed-mode-stack-walker-part-2/
	void getStackTrace(Row &r, LPCTSTR lpFileName, PCSTR pPath) {
		IDebugClient4* client;
		IDebugControl4* control;
		IDebugSymbols3* symbols;
		DEBUG_STACK_FRAME stackFrames[kulNumStackFramesToLog] = { 0 };
		ULONG numFrames = 0;
		char context[1024] = { 0 };
		ULONG type = 0;
		ULONG procID = 0;
		ULONG threadID = 0;
		ULONG contextSize = 0;
		

		// Create interfaces
		if (DebugCreate(__uuidof(IDebugClient), (void**)&client) != S_OK) {
			LOG(ERROR) << "DebugCreate failed while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, NULL, NULL);
		}
		if ((client->QueryInterface(__uuidof(IDebugControl4), (void**)&control) != S_OK)
			|| (client->QueryInterface(__uuidof(IDebugSymbols), (void**)&symbols) != S_OK)) {
			LOG(ERROR) << "QueryInterface failed while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, control, symbols);
		}

		// Initialization
		if (symbols->SetImagePath(pPath) != S_OK) {
			LOG(ERROR) << "Failed to set image path to \"" << pPath << "\" while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, control, symbols);
		}
		if (symbols->SetSymbolPath("srv*C:\\Windows\\symbols*http://msdl.microsoft.com/download/symbols") != S_OK) {
			LOG(ERROR) << "Failed to set symbol path while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, control, symbols);
		}
		if (client->OpenDumpFile(lpFileName) != S_OK) {
			LOG(ERROR) << "Failed to open dump file while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, control, symbols);
		}
		if (control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK) {
			LOG(ERROR) << "Initial processing failed while debugging crash dump: " << lpFileName;
			return debugEngineCleanup(client, control, symbols);
		}

		// Get stack frames from dump
		if (control->GetStoredEventInformation(&type, &procID, &threadID, context, sizeof(context), &contextSize, NULL, 0, 0) == S_OK) {
			char* contextData = new char[kulNumStackFramesToLog*contextSize];
			symbols->SetScopeFromStoredEvent();
			HRESULT status = control->GetContextStackTrace(context, contextSize, stackFrames, ARRAYSIZE(stackFrames), contextData, kulNumStackFramesToLog*contextSize, contextSize, &numFrames);
			delete[] contextData;
			if (status != S_OK) {
				LOG(ERROR) << "Error getting context stack trace while debugging crash dump: " << lpFileName;
				return debugEngineCleanup(client, control, symbols);
			}
		}
		else {
			LOG(WARNING) << "GetStoredEventInformation failed for crash dump: " << lpFileName;
			if (control->GetStackTrace(0, 0, 0, stackFrames, ARRAYSIZE(stackFrames), &numFrames) != S_OK) {
				LOG(ERROR) << "Error getting stack trace while debugging crash dump: " << lpFileName;
			}
		}
		
		std::stringstream stackTrace;
		BOOL firstFrame = true;
		for (ULONG frame = 0; frame < numFrames; frame++) {
			char name[512] = { 0 };
			unsigned __int64 offset = 0;

			if (!firstFrame) stackTrace << ",";
			firstFrame = false;
			if (symbols->GetNameByOffset(stackFrames[frame].InstructionOffset, name, ARRAYSIZE(name) - 1, NULL, &offset) == S_OK) {
				stackTrace << name << "+0x" << std::hex << offset;
			}
			stackTrace << "(0x" << std::hex << stackFrames[frame].InstructionOffset;
			stackTrace << ")";
		}
		r["stack_trace"] = stackTrace.str();

		// Cleanup
		return debugEngineCleanup(client, control, symbols);
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
				Row r;
				extractDumpInfo(r, iterator->path().generic_string().c_str());
				getStackTrace(r, iterator->path().generic_string().c_str(), r.at("path").c_str());
				if (!r.empty()) results.push_back(r);
			}
			++iterator;
		}

		return results;
	}
}
}