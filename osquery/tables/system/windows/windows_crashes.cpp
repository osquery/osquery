/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

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

class MinidumpOutputCallbacks : public IDebugOutputCallbacks {
public:
	osquery::Row* r;

	MinidumpOutputCallbacks(osquery::Row* r) {
		this->r = r;
	}

	STDMETHODIMP MinidumpOutputCallbacks::QueryInterface(THIS_ _In_ REFIID InterfaceId, _Out_ PVOID* Interface) {
		*Interface = NULL;
		if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
			IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks))) {
			*Interface = (IDebugOutputCallbacks *)this;
			AddRef();
			return S_OK;
		}
		else {
			return E_NOINTERFACE;
		}
	}

	STDMETHODIMP_(ULONG) MinidumpOutputCallbacks::AddRef(THIS) {
		return 1;
	}

	STDMETHODIMP_(ULONG) MinidumpOutputCallbacks::Release(THIS) {
		return 0;
	}

	STDMETHODIMP MinidumpOutputCallbacks::Output(THIS_ _In_ ULONG Mask, _In_ PCSTR Text) {
		if ((Mask & DEBUG_OUTPUT_NORMAL) == 0) {
			return S_FALSE;
		}

		std::string output(Text);
		auto cmd = processOutput(output);
		if (cmd == std::string("r")) {
			(*r)["registers"] = output;
		}
		else if (cmd.find("lm f a") != std::string::npos) {
			(*r)["module"] = findModulePath(output);
		}
		else if (cmd.find("lm f") != std::string::npos) {
			(*r)["path"] = findModulePath(output);
		}
		else {
			return S_FALSE;
		}
		return S_OK;
	}

	std::string processOutput(std::string& output) {
		std::istringstream preprocessed(output);
		std::ostringstream postprocessed;
		std::string cmd;
		std::string line;

		// Get the command that was executed
		std::getline(preprocessed, cmd);
		// Perform some additional cleaning on the output
		while (std::getline(preprocessed, line)) {
			if (
				// This comes from the "r" command if .ecxr is successful
				(line.find("Last set context:") != std::string::npos) ||
				// Remove natvis error messages that screw up column formatting
				(line.find("No .natvis files found") != std::string::npos)
				) {
				continue;
			}
			postprocessed << line + "\n";
		}
		output = postprocessed.str();
		return cmd;
	}

	std::string findModulePath(std::string output) {
		// Find the path of the first module
		auto location = output.find(":\\");
		if (location == std::string::npos) {
			return std::string();
		}
		auto firstPath = output.substr(location - 1);
		// Trim the rest of the output so we get just the module path
		location = firstPath.find("\n");
		return firstPath.substr(0, location);
	}
};

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kLocalDumpsRegKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error "
    "Reporting\\LocalDumps";
const std::string kDumpFolderRegPath = kLocalDumpsRegKey + "\\DumpFolder";
const std::string kFallbackFolder = "%TMP%";
const std::string kDumpFileExtension = ".dmp";
const unsigned long kNumStackFramesToLog = 10;
const std::map<unsigned long long, std::string> kMinidumpTypeFlags = {
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
const std::vector<MINIDUMP_STREAM_TYPE> kStreamTypes = {ExceptionStream,
                                                        ModuleListStream,
                                                        ThreadListStream,
                                                        MemoryListStream,
                                                        SystemInfoStream,
                                                        MiscInfoStream};

Status logAndStoreTID(const MINIDUMP_EXCEPTION_STREAM* stream,
                      unsigned int& tid,
                      Row& r) {
  if ((stream == nullptr) || (stream->ThreadId == 0)) {
    return Status(1);
  }

  r["tid"] = BIGINT(stream->ThreadId);
  tid = stream->ThreadId;
  return Status();
}

/*
Log & store exception info, and the exception message for errors with defined
parameters
*/
Status logAndStoreExceptionInfo(const MINIDUMP_EXCEPTION_STREAM* stream,
                       unsigned long long& exAddr,
                       Row& r) {
  if (stream == nullptr) {
    return Status(1);
  }
  auto ex = stream->ExceptionRecord;

  std::ostringstream exCodeStr;
  exCodeStr << "0x" << std::hex << ex.ExceptionCode;
  if (exCodeStr.fail()) {
	  return Status(1);
  }
  r["exception_code"] = exCodeStr.str();

  std::ostringstream exAddrStr;
  exAddrStr << "0x" << std::hex << ex.ExceptionAddress;
  if (exAddrStr.fail()) {
	  return Status(1);
  }
  r["exception_address"] = exAddrStr.str();
  exAddr = ex.ExceptionAddress;

  std::ostringstream errorMsg;
  if ((ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) &&
      (ex.NumberParameters == 2)) {
    std::ostringstream memAddrStr;
    memAddrStr << "0x" << std::hex << ex.ExceptionInformation[1];

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
  }
  else if ((ex.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
	  (ex.NumberParameters == 3)) {
	std::ostringstream memAddrStr;
	memAddrStr << "0x" << std::hex << ex.ExceptionInformation[1];

	std::ostringstream ntstatusStr;
	ntstatusStr << "0x" << std::hex << ex.ExceptionInformation[2];

	errorMsg << "The instruction at " << exAddrStr.str()
			 << " referenced memory at " << memAddrStr.str() << "."
			 << " The required data was not placed into memory because of"
			 << " an I/O error status of " << ntstatusStr.str() << ".";
	r["exception_message"] = errorMsg.str();
  }

  return Status();
}

Status logPID(const MINIDUMP_MISC_INFO* stream, Row& r) {
  if ((stream == nullptr) || !(stream->Flags1 & MINIDUMP_MISC1_PROCESS_ID)) {
    return Status(1);
  }

  r["pid"] = BIGINT(stream->ProcessId);
  return Status();
}

Status logProcessCreateTime(const MINIDUMP_MISC_INFO* stream, Row& r) {
  if ((stream == nullptr) || !(stream->Flags1 & MINIDUMP_MISC1_PROCESS_TIMES)) {
    return Status(1);
  }

  time_t procTimestamp = stream->ProcessCreateTime;
  struct tm gmt;
  char timeBuff[64];
  memset(timeBuff, 0, 64);
  gmtime_s(&gmt, &procTimestamp);
  strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);
  r["process_create_time"] = timeBuff;
  return Status();
}

Status logOSVersion(const MINIDUMP_SYSTEM_INFO* stream, Row& r) {
  if (stream == nullptr) {
    return Status(1);
  }

  r["major_version"] = INTEGER(stream->MajorVersion);
  r["minor_version"] = INTEGER(stream->MinorVersion);
  r["build_number"] = INTEGER(stream->BuildNumber);
  return Status();
}

Status logPEVersion(const MINIDUMP_MODULE_LIST* stream,
                           unsigned char* const dumpBase,
                           Row& r) {
  if (stream == nullptr) {
    return Status(1);
  }

  auto exeModule = stream->Modules[0];
  auto versionInfo = exeModule.VersionInfo;
  std::ostringstream versionStr;
  versionStr << ((versionInfo.dwFileVersionMS >> 16) & 0xffff) << "."
             << ((versionInfo.dwFileVersionMS >> 0) & 0xffff) << "."
             << ((versionInfo.dwFileVersionLS >> 16) & 0xffff) << "."
             << ((versionInfo.dwFileVersionLS >> 0) & 0xffff);
  r["version"] = versionStr.str();

  return Status();
}

// Pulls the memory at target address from the Minidump
void* getMemAtTarget(const MINIDUMP_MEMORY_LIST* stream,
                     unsigned long long target,
                     unsigned char* const dumpBase) {
  if (stream == nullptr) {
    return nullptr;
  }

  for (unsigned int i = 0; i < stream->NumberOfMemoryRanges; i++) {
    auto memRange = stream->MemoryRanges[i];
    if ((memRange.StartOfMemoryRange <= target) &&
        (target < (memRange.StartOfMemoryRange + memRange.Memory.DataSize))) {
      auto offset = target - memRange.StartOfMemoryRange;
      return static_cast<void*>(dumpBase + memRange.Memory.Rva + offset);
    }
  }
  return nullptr;
}

Status storeTEBAndPEB(const MINIDUMP_THREAD_LIST* threadStream,
                      const MINIDUMP_MEMORY_LIST* memStream,
                      unsigned char* const dumpBase,
                      unsigned int tid,
                      TEB*& teb,
                      PEB*& peb) {
  if ((threadStream == nullptr) || (memStream == nullptr)) {
    return Status(1);
  }

  unsigned long long tebAddr = 0;
  for (unsigned int i = 0; i < threadStream->NumberOfThreads; i++) {
    auto thread = threadStream->Threads[i];
    if (thread.ThreadId == tid) {
      tebAddr = thread.Teb;
    }
  }
  if (tebAddr == 0) {
    return Status(1);
  }

  auto result = getMemAtTarget(memStream, tebAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }
  teb = static_cast<TEB*>(result);

  auto pebAddr =
      reinterpret_cast<unsigned long long>(teb->ProcessEnvironmentBlock);
  result = getMemAtTarget(memStream, pebAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }
  peb = static_cast<PEB*>(result);

  return Status();
}

Status logBeingDebugged(const PEB* peb, Row& r) {
  if (peb == nullptr) {
    return Status(1);
  }

  r["being_debugged"] = BIGINT(static_cast<unsigned long>(peb->BeingDebugged));
  return Status();
}

Status storeProcessParams(const MINIDUMP_MEMORY_LIST* stream,
                          unsigned char* const dumpBase,
                          const PEB* peb,
                          RTL_USER_PROCESS_PARAMETERS*& params) {
  if ((stream == nullptr) || (peb == nullptr)) {
    return Status(1);
  }

  auto paramsAddr =
      reinterpret_cast<unsigned long long>(peb->ProcessParameters);
  auto result = getMemAtTarget(stream, paramsAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }
  params = static_cast<RTL_USER_PROCESS_PARAMETERS*>(result);
  return Status();
}

Status logProcessCmdLine(const MINIDUMP_MEMORY_LIST* stream,
                         unsigned char* const dumpBase,
                         const RTL_USER_PROCESS_PARAMETERS* params,
                         Row& r) {
  if ((stream == nullptr) || (params == nullptr)) {
    return Status(1);
  }

  auto cmdLineAddr =
      reinterpret_cast<unsigned long long>(params->CommandLine.Buffer);
  auto result = getMemAtTarget(stream, cmdLineAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }

  auto cmdLine = static_cast<wchar_t*>(result);
  r["command_line"] = wstringToString(cmdLine);
  return Status();
}

Status logProcessCurDir(const MINIDUMP_MEMORY_LIST* stream,
                        unsigned char* const dumpBase,
                        const RTL_USER_PROCESS_PARAMETERS* params,
                        Row& r) {
  if ((stream == nullptr) || (params == nullptr)) {
    return Status(1);
  }

  // Offset 0x38 is from WinDbg: dt nt!_RTL_USER_PROCESS_PARAMETERS
  auto curDirStruct = reinterpret_cast<const UNICODE_STRING*>(
      reinterpret_cast<const unsigned char*>(params) + 0x38);
  auto curDirAddr = reinterpret_cast<unsigned long long>(curDirStruct->Buffer);
  auto result = getMemAtTarget(stream, curDirAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }
  auto curDir = static_cast<wchar_t*>(result);
  r["current_directory"] =
      wstringToString(std::wstring(curDir, curDirStruct->Length / 2).c_str());
  return Status();
}

Status logProcessEnvVars(const MINIDUMP_MEMORY_LIST* stream,
                         unsigned char* const dumpBase,
                         const RTL_USER_PROCESS_PARAMETERS* params,
                         Row& r) {
  if ((stream == nullptr) || (params == nullptr)) {
    return Status(1);
  }

  // Offset 0x80 is from WinDbg: dt nt!_RTL_USER_PROCESS_PARAMETERS
  auto envVarsAddr = reinterpret_cast<const unsigned long long*>(
      reinterpret_cast<const unsigned char*>(params) + 0x80);
  auto result = getMemAtTarget(stream, *envVarsAddr, dumpBase);
  if (result == nullptr) {
    return Status(1);
  }
  auto envVars = static_cast<wchar_t*>(result);

  // Loop through environment variables and log those of interest
  // The environment variables are stored in the following format:
  // Var1=Value1\0Var2=Value2\0Var3=Value3\0 ... VarN=ValueN\0\0
  wchar_t* ptr = envVars;
  while (*ptr != '\0') {
    auto envVar = wstringToString(std::wstring(ptr).c_str());
    auto pos = envVar.find('=');
    auto varName = envVar.substr(0, pos);
    auto varValue = envVar.substr(pos + 1, envVar.length());

    if (varName == "COMPUTERNAME") {
      r["machine_name"] = varValue;
    } else if (varName == "USERNAME") {
      r["username"] = varValue;
    }

    ptr += envVar.length() + 1;
  }
  return Status();
}

Status logDumpTime(const MINIDUMP_HEADER* header, Row& r) {
  if (header == nullptr) {
    return Status(1);
  }

  time_t dumpTimestamp = header->TimeDateStamp;
  struct tm gmt;
  char timeBuff[64];
  memset(timeBuff, 0, 64);
  gmtime_s(&gmt, &dumpTimestamp);
  strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S UTC", &gmt);
  r["datetime"] = timeBuff;
  return Status();
}

Status logAndStoreDumpType(const MINIDUMP_HEADER* header,
                           unsigned long long& flags,
                           Row& r) {
  if (header == nullptr) {
    return Status(1);
  }

  std::ostringstream activeFlags;
  bool firstString = true;
  // Loop through MINIDUMP_TYPE flags and log the ones that are set
  for (auto const& flag : kMinidumpTypeFlags) {
    if (header->Flags & flag.first) {
      if (!firstString) {
        activeFlags << ",";
      }
      firstString = false;
      activeFlags << flag.second;
    }
  }
  r["type"] = activeFlags.str();
  flags = header->Flags;
  return Status();
}

void debugEngineCleanup(IDebugClient5* client,
                        IDebugControl4* control,
                        IDebugSymbols3* symbols) {
  if (symbols != nullptr) {
    symbols->Release();
  }
  if (control != nullptr) {
    control->Release();
  }
  if (client != nullptr) {
    client->SetOutputCallbacks(NULL);
    client->EndSession(DEBUG_END_PASSIVE);
    client->Release();
  }
  return;
}

Status logStackTrace(const char* fileName, IDebugControl4* control, IDebugSymbols3* symbols, Row& r) {
	char context[1024] = { 0 };
	unsigned long type = 0;
	unsigned long procID = 0;
	unsigned long threadID = 0;
	unsigned long contextSize = 0;
	unsigned long numFrames = 0;
	DEBUG_STACK_FRAME stackFrames[kNumStackFramesToLog] = { 0 };

	// Get stack frames, either with or without event context
	if (control->GetStoredEventInformation(&type,
		&procID,
		&threadID,
		context,
		sizeof(context),
		&contextSize,
		NULL,
		0,
		0) == S_OK) {
		auto contextData = new char[kNumStackFramesToLog * contextSize];
		symbols->SetScopeFromStoredEvent();
		auto status = control->GetContextStackTrace(context,
			contextSize,
			stackFrames,
			ARRAYSIZE(stackFrames),
			contextData,
			kNumStackFramesToLog * contextSize,
			contextSize,
			&numFrames);
		delete[] contextData;
		if (status != S_OK) {
			LOG(ERROR)
				<< "Error getting context stack trace while debugging crash dump: "
				<< fileName;
			return Status(1);
		}
	}
	else {
		if (control->GetStackTrace(
			0, 0, 0, stackFrames, ARRAYSIZE(stackFrames), &numFrames) != S_OK) {
			LOG(ERROR) << "Error getting stack trace while debugging crash dump: "
				<< fileName;
			return Status(1);
		}
	}

	// Then, log the stack frames
	std::ostringstream stackTrace;
	auto firstFrame = true;
	for (unsigned long frame = 0; frame < numFrames; frame++) {
		char name[512] = { 0 };
		unsigned long long offset = 0;

		if (!firstFrame) {
			stackTrace << ",";
		}
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
	return Status();
}

Status logRegisters(IDebugClient5* client, IDebugControl4* control) {
	IDebugRegisters2* registers;
	if (client->QueryInterface(__uuidof(IDebugRegisters), (void**)&registers) != S_OK) {
		return Status(1);
	}

	control->Execute(DEBUG_OUTCTL_THIS_CLIENT, ".ecxr", DEBUG_EXECUTE_ECHO);
	auto status = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "r", DEBUG_EXECUTE_ECHO);
	return (status == S_OK) ? Status() : Status(1);
}

Status logPEPath(IDebugClient5* client, IDebugControl4* control) {
	auto status = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "lm f", DEBUG_EXECUTE_ECHO);
	return (status == S_OK) ? Status() : Status(1);
}

Status logModulePath(IDebugClient5* client, IDebugControl4* control, Row r) {
	std::string cmd = "lm f a " + r["exception_address"];
	auto status = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd.c_str(), DEBUG_EXECUTE_ECHO);
	return (status == S_OK) ? Status() : Status(1);
}

/*
Note: appears to only detect unmanaged stack frames.
See http://blog.steveniemitz.com/building-a-mixed-mode-stack-walker-part-2/
*/
void processDebugEngine(const char* fileName, Row& r) {
  IDebugClient5* client;
  IDebugControl4* control;
  IDebugSymbols3* symbols;
  MinidumpOutputCallbacks callback(&r);

  // Create interfaces
  if (DebugCreate(__uuidof(IDebugClient5), (void**)&client) != S_OK) {
    LOG(ERROR) << "DebugCreate failed while debugging crash dump: " << fileName;
    return debugEngineCleanup(client, nullptr, nullptr);
  }
  if ((client->QueryInterface(__uuidof(IDebugControl4), (void**)&control) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugSymbols3), (void**)&symbols) !=
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
  client->SetOutputCallbacks(&callback);

  // Extract information for the row
  logStackTrace(fileName, control, symbols, r);
  logPEPath(client, control);
  logModulePath(client, control, r);
  logRegisters(client, control);

  // Cleanup
  return debugEngineCleanup(client, control, symbols);
}

void processDumpStreams(const char* fileName, Row& r) {
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
  auto dumpMapFile =
      CreateFileMapping(dumpFile, NULL, PAGE_READONLY, 0, 0, NULL);
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

  for (auto stream : kStreamTypes) {
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
  unsigned long long exAddr = 0;
  TEB* teb = nullptr;
  PEB* peb = nullptr;
  RTL_USER_PROCESS_PARAMETERS* params = nullptr;
  logAndStoreDumpType(header, dumpFlags, r);
  logAndStoreTID(exceptionStream, tid, r);
  storeTEBAndPEB(threadStream, memoryStream, dumpBaseAddr, tid, teb, peb);
  storeProcessParams(memoryStream, dumpBaseAddr, peb, params);
  logAndStoreExceptionInfo(exceptionStream, exAddr, r);

  // Then, process everything else
  r["crash_path"] = fileName;
  logDumpTime(header, r);
  logPID(miscStream, r);
  logProcessCreateTime(miscStream, r);
  logOSVersion(systemStream, r);
  logPEVersion(moduleStream, dumpBaseAddr, r);
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
                                kLocalDumpsRegKey + "\" AND path = \"" +
                                kDumpFolderRegPath + "\"";
  SQL dumpFolderResults(dumpFolderQuery);

  if (dumpFolderResults.rows().empty()) {
    LOG(WARNING)
        << "No crash dump folder found in registry; using fallback location of "
        << kFallbackFolder;
    dumpFolderLocation = kFallbackFolder;
  } else {
    RowData dumpFolderRowData = dumpFolderResults.rows()[0].at("data");
    dumpFolderLocation = dumpFolderRowData;
  }

  // Fill in any environment variables
  char expandedDumpFolderLocation[MAX_PATH];
  ExpandEnvironmentStrings(
      dumpFolderLocation.c_str(), expandedDumpFolderLocation, MAX_PATH);

  if (!fs::exists(expandedDumpFolderLocation) ||
      !fs::is_directory(expandedDumpFolderLocation)) {
    LOG(ERROR) << "Invalid crash dump directory: "
               << expandedDumpFolderLocation;
    return results;
  }

  // Enumerate and process crash dumps
  fs::directory_iterator iterator(expandedDumpFolderLocation);
  fs::directory_iterator endIterator;
  while (iterator != endIterator) {
    std::string extension = iterator->path().extension().string();
    std::transform(
        extension.begin(), extension.end(), extension.begin(), ::tolower);
    if (fs::is_regular_file(*iterator) &&
        (extension.compare(kDumpFileExtension) == 0)) {
      Row r;
      processDumpStreams(iterator->path().generic_string().c_str(), r);
      processDebugEngine(iterator->path().generic_string().c_str(), r);
      if (!r.empty()) {
        results.push_back(r);
      }
    }
    ++iterator;
  }

  return results;
}
}
}