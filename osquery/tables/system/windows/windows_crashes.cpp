// Copyright 2004-present Facebook. All Rights Reserved.

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winternl.h>
#pragma warning(push)
/*
C:\Program Files (x86)\Windows Kits\8.1\Include\um\DbgHelp.h(3190):
warning C4091: 'typedef ': ignored on left of '' when no variable is declared
*/
#pragma warning(disable : 4091)
#include <DbgHelp.h>
#pragma warning(pop)
#include <DbgEng.h>

#include <boost/filesystem.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

const std::string localDumpsRegKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error "
    "Reporting\\LocalDumps";
const std::string dumpFolderRegPath = localDumpsRegKey + "\\DumpFolder";
const std::string fallbackFolder = "%TMP%";
const std::string dumpFileExtension = ".dmp";
const unsigned long numStackFramesToLog = 10;
const std::map<unsigned long long, std::string> minidumpTypeFlags = {
    {0x00000000, "MiniDumpNormal"},
    {0x00000001, "MiniDumpWithDataSegs"},
    {0x00000002, "MiniDumpWithFullMemory"},
    {0x00000004, "MiniDumpWithHandleData"},
    {0x00000008, "MiniDumpFilterMemory"},
    {0x00000010, "MiniDumpScanMemory"},
    {0x00000020, "MiniDumpWithUnloadedModules"},
    {0x00000040, "MiniDumpWithIndirectlyReferencedMemory"},
    {0x00000080, "MiniDumpFilterModulePaths"},
    {0x00000100, "MiniDumpWithProcessThreadData"},
    {0x00000200, "MiniDumpWithPrivateReadWriteMemory"},
    {0x00000400, "MiniDumpWithoutOptionalData"},
    {0x00000800, "MiniDumpWithFullMemoryInfo"},
    {0x00001000, "MiniDumpWithThreadInfo"},
    {0x00002000, "MiniDumpWithCodeSegs"},
    {0x00004000, "MiniDumpWithoutAuxiliaryState"},
    {0x00008000, "MiniDumpWithFullAuxiliaryState"},
    {0x00010000, "MiniDumpWithPrivateWriteCopyMemory"},
    {0x00020000, "MiniDumpIgnoreInaccessibleMemory"},
    {0x00040000, "MiniDumpWithTokenInformation"},
    {0x00080000, "MiniDumpWithModuleHeaders"},
    {0x00100000, "MiniDumpFilterTriage"},
    {0x001fffff, "MiniDumpValidTypeFlags"}};
const std::vector<MINIDUMP_STREAM_TYPE> streamTypes = {ExceptionStream,
                                                       ModuleListStream,
                                                       ThreadListStream,
                                                       MemoryListStream,
                                                       SystemInfoStream,
                                                       MiscInfoStream};

Status logAndStoreTID(MINIDUMP_EXCEPTION_STREAM* stream, unsigned int& tid, Row& r) {
	if (stream == nullptr) return Status(1);
	if (stream->ThreadId == 0) return Status(1);

	r["tid"] = BIGINT(stream->ThreadId);
	tid = stream->ThreadId;
	return Status(0);
}

Status logAndStoreExceptionCodeAndAddr(MINIDUMP_EXCEPTION_STREAM* stream, unsigned int& exCode, unsigned long long& exAddr, Row& r) {
	if (stream == nullptr) return Status(1);
	MINIDUMP_EXCEPTION ex = stream->ExceptionRecord;
	std::ostringstream exCodeStr;
	exCodeStr << "0x" << std::hex << ex.ExceptionCode;

	if (exCodeStr.fail()) return Status(1);
	r["exception_code"] = exCodeStr.str();
	exCode = ex.ExceptionCode;

	std::ostringstream exAddrStr;
	exAddrStr << "0x" << std::hex << ex.ExceptionAddress;

	if (exAddrStr.fail()) return Status(1);
	r["exception_address"] = exAddrStr.str();
	exAddr = ex.ExceptionAddress;
	return Status(0);
}

/*
Log the exception message for errors with defined parameters
(see ExceptionInformation @ https://msdn.microsoft.com/en-us/library/windows/desktop/ms680367(v=vs.85).aspx)
*/
Status logExceptionMsg(MINIDUMP_EXCEPTION_STREAM* stream, unsigned int exCode, unsigned long long exAddr, Row& r) {
	if (stream == nullptr) return Status(1);
	MINIDUMP_EXCEPTION ex = stream->ExceptionRecord;

	if ((ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) &&
		(ex.NumberParameters == 2)) {
		std::ostringstream errorMsg;
		std::ostringstream memAddrStr;
		memAddrStr << "0x" << std::hex << ex.ExceptionInformation[1];
		std::ostringstream exAddrStr;
		exAddrStr << "0x" << std::hex << exAddr;

		errorMsg << "The instruction at " << exAddrStr.str()
			<< " referenced memory at " << memAddrStr.str() << ".";
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
		return Status(0);
	}

	return Status(1);
}

Status logRegisters(MINIDUMP_EXCEPTION_STREAM* stream, unsigned char* dumpBase, Row& r) {
	if (stream == nullptr) return Status(1);
	MINIDUMP_EXCEPTION ex = stream->ExceptionRecord;
	auto threadContext =
		reinterpret_cast<CONTEXT*>(dumpBase + stream->ThreadContext.Rva);

	std::ostringstream registers;
	// Registers are hard-coded for x64 system b/c lack of C++ reflection on
	// CONTEXT object
	registers << "rax:0x" << std::hex << threadContext->Rax;
	registers << " rbx:0x" << std::hex << threadContext->Rbx;
	registers << " rcx:0x" << std::hex << threadContext->Rcx;
	registers << " rdx:0x" << std::hex << threadContext->Rdx;
	registers << " rdi:0x" << std::hex << threadContext->Rdi;
	registers << " rsi:0x" << std::hex << threadContext->Rsi;
	registers << " rbp:0x" << std::hex << threadContext->Rbp;
	registers << " rsp:0x" << std::hex << threadContext->Rsp;
	registers << " r8:0x" << std::hex << threadContext->R8;
	registers << " r9:0x" << std::hex << threadContext->R9;
	registers << " r10:0x" << std::hex << threadContext->R10;
	registers << " r11:0x" << std::hex << threadContext->R11;
	registers << " r12:0x" << std::hex << threadContext->R12;
	registers << " r13:0x" << std::hex << threadContext->R13;
	registers << " r14:0x" << std::hex << threadContext->R14;
	registers << " r15:0x" << std::hex << threadContext->R15;
	registers << " rip:0x" << std::hex << threadContext->Rip;
	registers << " segcs:0x" << std::hex << threadContext->SegCs;
	registers << " segds:0x" << std::hex << threadContext->SegDs;
	registers << " seges:0x" << std::hex << threadContext->SegEs;
	registers << " segfs:0x" << std::hex << threadContext->SegFs;
	registers << " seggs:0x" << std::hex << threadContext->SegGs;
	registers << " segss:0x" << std::hex << threadContext->SegSs;
	registers << " eflags:0x" << std::hex << threadContext->EFlags;
	r["registers"] = registers.str();
	return Status(0);
}

Status logPID(MINIDUMP_MISC_INFO* stream, Row& r) {
	if (stream == nullptr) return Status(1);
	if (!(stream->Flags1 & MINIDUMP_MISC1_PROCESS_ID)) return Status(1);

	r["pid"] = BIGINT(stream->ProcessId);
	return Status(0);
}

Status logProcessCreateTime(MINIDUMP_MISC_INFO* stream, Row& r) {
	if (stream == nullptr) return Status(1);
	if (!(stream->Flags1 & MINIDUMP_MISC1_PROCESS_TIMES)) return Status(1);

	time_t procTimestamp = stream->ProcessCreateTime;
	struct tm gmt;
	char timeBuff[64];
	gmtime_s(&gmt, &procTimestamp);
	strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);

	r["process_create_time"] = timeBuff;
	return Status(0);
}

Status logOSVersion(MINIDUMP_SYSTEM_INFO* stream, Row &r) {
	if (stream == nullptr) return Status(1);
	r["major_version"] = INTEGER(stream->MajorVersion);
	r["minor_version"] = INTEGER(stream->MinorVersion);
	r["build_number"] = INTEGER(stream->BuildNumber);
	return Status(0);
}

Status logPEPathAndVersion(MINIDUMP_MODULE_LIST* stream, unsigned char* dumpBase, Row &r) {
	if (stream == nullptr) return Status(1);
	MINIDUMP_MODULE exeModule = stream->Modules[0];

	auto exePath = reinterpret_cast<MINIDUMP_STRING*>(dumpBase + exeModule.ModuleNameRva);
	r["path"] = wstringToString(exePath->Buffer);

	VS_FIXEDFILEINFO versionInfo = exeModule.VersionInfo;
	std::ostringstream versionStr;
	versionStr << ((versionInfo.dwFileVersionMS >> 16) & 0xffff) << "."
		<< ((versionInfo.dwFileVersionMS >> 0) & 0xffff) << "."
		<< ((versionInfo.dwFileVersionLS >> 16) & 0xffff) << "."
		<< ((versionInfo.dwFileVersionLS >> 0) & 0xffff);
	r["version"] = versionStr.str();

	return Status(0);
}

Status logCrashedModule(MINIDUMP_MODULE_LIST* stream, unsigned char* dumpBase, unsigned long long exAddr, Row &r) {
	if (stream == nullptr) return Status(1);
	for (unsigned int i = 0; i < stream->NumberOfModules; i++) {
		MINIDUMP_MODULE module = stream->Modules[i];
		// Is the exception address within this module's memory space?
		if ((module.BaseOfImage <= exAddr) &&
			(exAddr <= (module.BaseOfImage + module.SizeOfImage))) {
			auto modulePath = reinterpret_cast<MINIDUMP_STRING*>(dumpBase + module.ModuleNameRva);
			r["module"] = wstringToString(modulePath->Buffer);
			return Status(0);
		}
	}

	return Status(1);
}

// Pulls the memory range containing target address from the Minidump
MINIDUMP_MEMORY_DESCRIPTOR* getMemRange(
	unsigned long long target, MINIDUMP_MEMORY_LIST* memoryListStream) {
	if (memoryListStream == nullptr) return nullptr;// Status(1);
	for (unsigned int i = 0; i < memoryListStream->NumberOfMemoryRanges; i++) {
		MINIDUMP_MEMORY_DESCRIPTOR memRange = memoryListStream->MemoryRanges[i];
		if ((memRange.StartOfMemoryRange <= target) &&
			(target < (memRange.StartOfMemoryRange + memRange.Memory.DataSize))) {
			return &memoryListStream->MemoryRanges[i];
		}
	}
	return nullptr;
}

Status storeTEBAndPEB(MINIDUMP_THREAD_LIST* threadStream, MINIDUMP_MEMORY_LIST* memStream, unsigned char* dumpBase, unsigned int tid, TEB*& teb, PEB*& peb) {
	if ((threadStream == nullptr) || (memStream == nullptr)) return Status(1);
	unsigned long long tebAddr = 0;
	for (unsigned int i = 0; i < threadStream->NumberOfThreads; i++) {
		MINIDUMP_THREAD thread = threadStream->Threads[i];
		if (thread.ThreadId == tid) {
			tebAddr = thread.Teb;
		}
	}
	
	if (tebAddr == 0) return Status(1);
	MINIDUMP_MEMORY_DESCRIPTOR* tebMem = getMemRange(tebAddr, memStream);
	if (tebMem == nullptr) return Status(1);
	unsigned long long tebOffset = tebAddr - tebMem->StartOfMemoryRange;
	teb = reinterpret_cast<TEB*>(dumpBase + tebMem->Memory.Rva + tebOffset);

	auto pebAddr =
		reinterpret_cast<unsigned long long>(teb->ProcessEnvironmentBlock);
	MINIDUMP_MEMORY_DESCRIPTOR* pebMem = getMemRange(pebAddr, memStream);
	if (pebMem == nullptr) return Status(1);
	unsigned long long pebOffset = pebAddr - pebMem->StartOfMemoryRange;
	peb = reinterpret_cast<PEB*>(dumpBase + pebMem->Memory.Rva + pebOffset);

	return Status(0);
}

Status logBeingDebugged(PEB* peb, Row& r) {
	if (peb == nullptr) return Status(1);
	if (peb->BeingDebugged == TRUE) {
		r["being_debugged"] = "true";
	}
	else {
		r["being_debugged"] = "false";
	}
	return Status(0);
}

Status storeProcessParams(MINIDUMP_MEMORY_LIST* stream, unsigned char* dumpBase, PEB* peb, RTL_USER_PROCESS_PARAMETERS*& params) {
	if ((stream == nullptr) || (peb == nullptr)) return Status(1);
	auto paramsAddr =
		reinterpret_cast<unsigned long long>(peb->ProcessParameters);
	MINIDUMP_MEMORY_DESCRIPTOR* paramsMem = getMemRange(paramsAddr, stream);
	if (paramsMem == nullptr) return Status(1);
	unsigned long long paramsOffset = paramsAddr - paramsMem->StartOfMemoryRange;
	params = reinterpret_cast<RTL_USER_PROCESS_PARAMETERS*>(dumpBase + paramsMem->Memory.Rva + paramsOffset);
	return Status(0);
}

Status logProcessCmdLine(MINIDUMP_MEMORY_LIST* stream, unsigned char* dumpBase, RTL_USER_PROCESS_PARAMETERS* params, Row& r) {
	if ((stream == nullptr) || (params == nullptr)) return Status(1);
	auto cmdLineAddr =
		reinterpret_cast<unsigned long long>(params->CommandLine.Buffer);
	MINIDUMP_MEMORY_DESCRIPTOR* cmdLineMem = getMemRange(cmdLineAddr, stream);
	if (cmdLineMem == nullptr) return Status(1);
	unsigned long long cmdLineOffset = cmdLineAddr - cmdLineMem->StartOfMemoryRange;
	auto cmdLine = reinterpret_cast<wchar_t*>(dumpBase + cmdLineMem->Memory.Rva + cmdLineOffset);
	r["command_line"] = wstringToString(cmdLine);
	return Status(0);
}

Status logProcessCurDir(MINIDUMP_MEMORY_LIST* stream, unsigned char* dumpBase, RTL_USER_PROCESS_PARAMETERS* params, Row& r) {
	if ((stream == nullptr) || (params == nullptr)) return Status(1);
	// Offset 0x38 is from WinDbg: dt nt!_RTL_USER_PROCESS_PARAMETERS
	auto curDirStruct = reinterpret_cast<UNICODE_STRING*>(
		reinterpret_cast<unsigned char*>(params) + 0x38);
	auto curDirAddr = reinterpret_cast<unsigned long long>(curDirStruct->Buffer);
	MINIDUMP_MEMORY_DESCRIPTOR* curDirMem =
		getMemRange(curDirAddr, stream);
	if (curDirMem == nullptr) return Status(1);
	unsigned long long curDirOffset = curDirAddr - curDirMem->StartOfMemoryRange;
	auto curDir = reinterpret_cast<wchar_t*>(dumpBase + curDirMem->Memory.Rva + curDirOffset);
	r["current_directory"] = wstringToString(std::wstring(curDir, curDirStruct->Length / 2).c_str());
	return Status(0);
}

Status logProcessEnvVars(MINIDUMP_MEMORY_LIST* stream, unsigned char* dumpBase, RTL_USER_PROCESS_PARAMETERS* params, Row &r) {
	if ((stream == nullptr) || (params == nullptr)) return Status(1);
	// Offset 0x80 is from WinDbg: dt nt!_RTL_USER_PROCESS_PARAMETERS
	auto envVarsAddr = reinterpret_cast<unsigned long long*>(
		reinterpret_cast<unsigned char*>(params) + 0x80);
	MINIDUMP_MEMORY_DESCRIPTOR* envVarsMem =
		getMemRange(*envVarsAddr, stream);
	if (envVarsMem == nullptr) return Status(1);
	unsigned long long envOffset = *envVarsAddr - envVarsMem->StartOfMemoryRange;
	auto envVars = reinterpret_cast<wchar_t*>(dumpBase + envVarsMem->Memory.Rva + envOffset);

	// Loop through environment variables and log those of interest
	// The environment variables are stored in the following format:
	// Var1=Value1\0Var2=Value2\0Var3=Value3\0 ... VarN=ValueN\0\0
	wchar_t* ptr = envVars;
	while (*ptr != '\0') {
		std::string envVar = wstringToString(std::wstring(ptr).c_str());
		std::string::size_type pos = envVar.find('=');
		std::string varName = envVar.substr(0, pos);
		std::string varValue = envVar.substr(pos + 1, envVar.length());

		if (varName == "COMPUTERNAME") {
			r["machine_name"] = varValue;
		}
		else if (varName == "USERNAME") {
			r["username"] = varValue;
		}

		ptr += envVar.length() + 1;
	}
	return Status(0);
}

Status logDumpTime(MINIDUMP_HEADER* header, Row& r) {
	if (header == nullptr) return Status(1);
	time_t dumpTimestamp = header->TimeDateStamp;
	struct tm gmt;
	char timeBuff[64];
	gmtime_s(&gmt, &dumpTimestamp);
	strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);
	r["datetime"] = timeBuff;
	return Status(0);
}

Status logAndStoreDumpType(MINIDUMP_HEADER* header, Row& r, unsigned long long& flags) {
	if (header == nullptr) return Status(1);
	std::ostringstream activeFlags;
	bool firstString = true;
	// Loop through MINIDUMP_TYPE flags and log the ones that are set
	for (auto const& flag : minidumpTypeFlags) {
		if (header->Flags & flag.first) {
			if (!firstString) activeFlags << ",";
			firstString = false;
			activeFlags << flag.second;
		}
	}
	r["type"] = activeFlags.str();
	flags = header->Flags;
	return Status(0);
}

void debugEngineCleanup(IDebugClient4* client,
                        IDebugControl4* control,
                        IDebugSymbols3* symbols) {
  if (symbols != nullptr)
    symbols->Release();
  if (control != nullptr)
    control->Release();
  if (client != nullptr) {
    client->SetOutputCallbacks(NULL);
    client->EndSession(DEBUG_END_PASSIVE);
    client->Release();
  }
  return;
}

/*
Note: appears to only detect unmanaged stack frames.
See http://blog.steveniemitz.com/building-a-mixed-mode-stack-walker-part-2/
*/
void logStackTrace(Row& r, const char* fileName) {
  IDebugClient4* client;
  IDebugControl4* control;
  IDebugSymbols3* symbols;
  DEBUG_STACK_FRAME stackFrames[numStackFramesToLog] = {0};
  unsigned long numFrames = 0;
  char context[1024] = {0};
  unsigned long type = 0;
  unsigned long procID = 0;
  unsigned long threadID = 0;
  unsigned long contextSize = 0;

  // Create interfaces
  if (DebugCreate(__uuidof(IDebugClient), (void**)&client) != S_OK) {
    LOG(ERROR) << "DebugCreate failed while debugging crash dump: " << fileName;
    return debugEngineCleanup(client, nullptr, nullptr);
  }
  if ((client->QueryInterface(__uuidof(IDebugControl4), (void**)&control) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugSymbols), (void**)&symbols) !=
       S_OK)) {
    LOG(ERROR) << "QueryInterface failed while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(client, control, symbols);
  }

  // Initialization
  if (symbols->SetImagePath(r["path"].c_str()) != S_OK) {
    LOG(ERROR) << "Failed to set image path to \"" << r["path"]
               << "\" while debugging crash dump: " << fileName;
    return debugEngineCleanup(client, control, symbols);
  }
  if (symbols->SetSymbolPath("srv*C:\\Windows\\symbols*http://"
                             "msdl.microsoft.com/download/symbols") != S_OK) {
    LOG(ERROR) << "Failed to set symbol path while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(client, control, symbols);
  }
  if (client->OpenDumpFile(fileName) != S_OK) {
    LOG(ERROR) << "Failed to open dump file while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(client, control, symbols);
  }
  if (control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK) {
    LOG(ERROR) << "Initial processing failed while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(client, control, symbols);
  }

  // Get stack frames from dump
  if (control->GetStoredEventInformation(&type,
                                         &procID,
                                         &threadID,
                                         context,
                                         sizeof(context),
                                         &contextSize,
                                         NULL,
                                         0,
                                         0) == S_OK) {
    char* contextData = new char[numStackFramesToLog * contextSize];
    symbols->SetScopeFromStoredEvent();
    long status =
        control->GetContextStackTrace(context,
                                      contextSize,
                                      stackFrames,
                                      ARRAYSIZE(stackFrames),
                                      contextData,
                                      numStackFramesToLog * contextSize,
                                      contextSize,
                                      &numFrames);
    delete[] contextData;
    if (status != S_OK) {
      LOG(ERROR)
          << "Error getting context stack trace while debugging crash dump: "
          << fileName;
      return debugEngineCleanup(client, control, symbols);
    }
  } else {
    LOG(WARNING) << "GetStoredEventInformation failed for crash dump: "
                 << fileName;
    if (control->GetStackTrace(
            0, 0, 0, stackFrames, ARRAYSIZE(stackFrames), &numFrames) != S_OK) {
      LOG(ERROR) << "Error getting stack trace while debugging crash dump: "
                 << fileName;
    }
  }

  std::ostringstream stackTrace;
  bool firstFrame = true;
  for (unsigned long frame = 0; frame < numFrames; frame++) {
    char name[512] = {0};
    unsigned long long offset = 0;

    if (!firstFrame)
      stackTrace << ",";
    firstFrame = false;
    if (symbols->GetNameByOffset(stackFrames[frame].InstructionOffset,
                                 name,
                                 ARRAYSIZE(name) - 1,
                                 NULL,
                                 &offset) == S_OK) {
      stackTrace << name << "+0x" << std::hex << offset;
    }
    stackTrace << "(0x" << std::hex << stackFrames[frame].InstructionOffset;
    stackTrace << ")";
  }
  r["stack_trace"] = stackTrace.str();

  // Cleanup
  return debugEngineCleanup(client, control, symbols);
}

void processDumpFile(Row& r, const char* fileName) {
  // Open the file
  auto dumpFile = CreateFile(fileName,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
  if (dumpFile == NULL) {
    unsigned long error = GetLastError();
    LOG(ERROR) << "Error opening crash dump file: " << fileName
               << " with error code " << error;
    return;
  }

  // Create file mapping object
  auto dumpMapFile = CreateFileMapping(dumpFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (dumpMapFile == NULL) {
    unsigned long error = GetLastError();
    LOG(ERROR) << "Error creating crash dump mapping object: " << fileName
               << " with error code " << error;
    CloseHandle(dumpFile);
    return;
  }

  // Map the file
  auto dumpBase = MapViewOfFile(dumpMapFile, FILE_MAP_READ, 0, 0, 0);
  if (dumpBase == NULL) {
    unsigned long error = GetLastError();
    LOG(ERROR) << "Error mapping crash dump file: " << fileName
               << " with error code " << error;
    CloseHandle(dumpMapFile);
    CloseHandle(dumpFile);
    return;
  }

  // Read dump streams
  auto header = static_cast<MINIDUMP_HEADER*>(dumpBase);
  MINIDUMP_EXCEPTION_STREAM* exceptionStream = nullptr;
  MINIDUMP_MODULE_LIST* moduleStream = nullptr;
  MINIDUMP_THREAD_LIST* threadStream = nullptr;
  MINIDUMP_MEMORY_LIST* memoryStream = nullptr;
  MINIDUMP_SYSTEM_INFO* systemStream = nullptr;
  MINIDUMP_MISC_INFO* miscStream = nullptr;

  for (auto stream : streamTypes) {
	  MINIDUMP_DIRECTORY* dumpStreamDir = 0;
	  void* dumpStream = 0;
	  unsigned long dumpStreamSize = 0;

	  BOOL dumpRead = MiniDumpReadDumpStream(
		  dumpBase, stream, &dumpStreamDir, &dumpStream, &dumpStreamSize);
	  if (!dumpRead) {
		  unsigned long dwError = GetLastError();
		  LOG(ERROR) << "Error reading stream " << stream
			  << " in crash dump file: " << fileName << " with error code "
			  << dwError;
		  continue;
	  }

    switch (stream) {
    case ThreadListStream:
		threadStream = static_cast<MINIDUMP_THREAD_LIST*>(dumpStream);
		break;
    case ModuleListStream:
		moduleStream = static_cast<MINIDUMP_MODULE_LIST*>(dumpStream);
		break;
    case MemoryListStream:
		memoryStream = static_cast<MINIDUMP_MEMORY_LIST*>(dumpStream);
		break;
    case ExceptionStream:
		exceptionStream = static_cast<MINIDUMP_EXCEPTION_STREAM*>(dumpStream);
		break;
    case SystemInfoStream:
		systemStream = static_cast<MINIDUMP_SYSTEM_INFO*>(dumpStream);
		break;
    case MiscInfoStream:
		miscStream = static_cast<MINIDUMP_MISC_INFO*>(dumpStream);
		break;
    default:
      LOG(ERROR) << "Attempting to process unsupported crash dump stream: "
                 << stream;
      break;
    }
  }

  auto dumpBaseAddr = static_cast<unsigned char*>(dumpBase);
  // Process dump info
  // First, run functions that store information for later processing
  unsigned long long dumpFlags = 0;
  unsigned int tid = 0;
  unsigned int exCode = 0;
  unsigned long long exAddr = 0;
  TEB* teb = nullptr;
  PEB* peb = nullptr;
  RTL_USER_PROCESS_PARAMETERS* params = nullptr;
  logAndStoreDumpType(header, r, dumpFlags);
  logAndStoreTID(exceptionStream, tid, r);
  storeTEBAndPEB(threadStream, memoryStream, dumpBaseAddr, tid, teb, peb);
  storeProcessParams(memoryStream, dumpBaseAddr, peb, params);
  logAndStoreExceptionCodeAndAddr(exceptionStream, exCode, exAddr, r);

  // Then, process everything else
  r["crash_path"] = fileName;
  logDumpTime(header, r);
  logExceptionMsg(exceptionStream, exCode, exAddr, r);
  logRegisters(exceptionStream, dumpBaseAddr, r);
  logPID(miscStream, r);
  logProcessCreateTime(miscStream, r);
  logOSVersion(systemStream, r);
  logPEPathAndVersion(moduleStream, dumpBaseAddr, r);
  logCrashedModule(moduleStream, dumpBaseAddr, exAddr, r);
  logBeingDebugged(peb, r);
  logProcessCmdLine(memoryStream, dumpBaseAddr, params, r);
  logProcessCurDir(memoryStream, dumpBaseAddr, params, r);
  logProcessEnvVars(memoryStream, dumpBaseAddr, params, r);

  // Cleanup
  UnmapViewOfFile(dumpBase);
  CloseHandle(dumpMapFile);
  CloseHandle(dumpFile);
  return;
}

QueryData genCrashLogs(QueryContext& context) {
  QueryData results;
  std::string dumpFolderLocation;

  // Query registry for crash dump folder
  std::string dumpFolderQuery = "SELECT data FROM registry WHERE key = \"" +
                                localDumpsRegKey + "\" AND path = \"" +
                                dumpFolderRegPath + "\"";
  SQL dumpFolderResults(dumpFolderQuery);

  if (dumpFolderResults.rows().empty()) {
    LOG(WARNING)
        << "No crash dump folder found in registry; using fallback location of "
        << fallbackFolder;
    dumpFolderLocation = fallbackFolder;
  } else {
    RowData dumpFolderRowData = dumpFolderResults.rows()[0].at("data");
    dumpFolderLocation = dumpFolderRowData;
  }

  // Fill in any environment variables
  char expandedDumpFolderLocation[MAX_PATH];
  ExpandEnvironmentStrings(
      dumpFolderLocation.c_str(), expandedDumpFolderLocation, MAX_PATH);

  if (!boost::filesystem::exists(expandedDumpFolderLocation) ||
      !boost::filesystem::is_directory(expandedDumpFolderLocation)) {
    LOG(ERROR) << "Invalid crash dump directory: "
               << expandedDumpFolderLocation;
    return results;
  }

  // Enumerate and process crash dumps
  boost::filesystem::directory_iterator iterator(expandedDumpFolderLocation);
  boost::filesystem::directory_iterator endIterator;
  while (iterator != endIterator) {
    std::string extension = iterator->path().extension().string();
    std::transform(
        extension.begin(), extension.end(), extension.begin(), ::tolower);
    if (boost::filesystem::is_regular_file(*iterator) &&
        (extension.compare(dumpFileExtension) == 0)) {
      Row r;
      processDumpFile(r, iterator->path().generic_string().c_str());
      logStackTrace(r, iterator->path().generic_string().c_str());
      if (!r.empty())
        results.push_back(r);
    }
    ++iterator;
  }

  return results;
}
}
}