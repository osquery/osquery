/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/env.h>
#include <osquery/utils/system/system.h>

#include <Winternl.h>
#pragma warning(push)
// C:\Program Files (x86)\Windows Kits\8.1\Include\um\DbgHelp.h(3190):
// warning C4091: 'typedef ': ignored on left of '' when no variable is
// declared
#pragma warning(disable : 4091)
#include <DbgHelp.h>
#pragma warning(pop)
#include <DbgEng.h>
#include <iomanip>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/process/process.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace alg = boost::algorithm;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kLocalDumpsRegKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error "
    "Reporting\\LocalDumps\\DumpFolder";
const std::string kSymbolPath =
    "C:\\ProgramData\\dbg\\sym;"
    "cache*C:\\ProgramData\\dbg\\sym;"
    "srv*C:\\ProgramData\\dbg\\sym*https://msdl.microsoft.com/download/symbols";
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

class RegisterOutputCallbacks : public IDebugOutputCallbacks {
 private:
  Row* r_ = nullptr;

 public:
  RegisterOutputCallbacks(Row* r) {
    this->r_ = r;
  }

  STDMETHODIMP RegisterOutputCallbacks::QueryInterface(
      THIS_ _In_ REFIID InterfaceId, _Out_ PVOID* Interface) {
    *Interface = nullptr;
    if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
        IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks))) {
      *Interface = (IDebugOutputCallbacks*)this;
      AddRef();
      return S_OK;
    } else {
      return E_NOINTERFACE;
    }
  }

  STDMETHODIMP_(ULONG) RegisterOutputCallbacks::AddRef(THIS) {
    return 1;
  }

  STDMETHODIMP_(ULONG) RegisterOutputCallbacks::Release(THIS) {
    return 0;
  }

  STDMETHODIMP RegisterOutputCallbacks::Output(THIS_ _In_ ULONG Mask,
                                               _In_ PCSTR Text) {
    if ((Mask & DEBUG_OUTPUT_NORMAL) == 0) {
      return S_FALSE;
    }

    // Remove CRLFs and extra whitespace
    std::istringstream stream(Text);
    std::string output;
    std::string reg;
    while (stream >> reg) {
      // Replace "=" with ":0x" to match darwin crashes table
      size_t ptr = reg.find("=");
      if (ptr != std::string::npos) {
        reg.replace(ptr, 1, ":0x");
      }

      if (!output.empty()) {
        output += ' ';
      }
      output += reg;
    }

    (*r_)["registers"] = output;
    return S_OK;
  }
};

// Log exception info, and the message when exception has defined parameters
Status logExceptionInfo(IDebugControl5* control, Row& r) {
  unsigned long type = 0;
  unsigned long procID = 0;
  unsigned long threadID = 0;
  DEBUG_LAST_EVENT_INFO_EXCEPTION ex = {0};
  if ((control->GetStoredEventInformation(&type,
                                          &procID,
                                          &threadID,
                                          nullptr,
                                          0,
                                          nullptr,
                                          &ex,
                                          sizeof(ex),
                                          nullptr) != S_OK) ||
      (type != DEBUG_EVENT_EXCEPTION)) {
    return Status(1);
  }
  auto record = ex.ExceptionRecord;

  std::ostringstream exCodeStr;
  exCodeStr << "0x" << std::hex << record.ExceptionCode;
  if (exCodeStr.fail()) {
    return Status(1);
  }
  r["exception_code"] = exCodeStr.str();

  std::ostringstream exAddrStr;
  exAddrStr << "0x" << std::hex << record.ExceptionAddress;
  if (exAddrStr.fail()) {
    return Status(1);
  }
  r["exception_address"] = exAddrStr.str();

  std::ostringstream errorMsg;
  if ((record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) &&
      (record.NumberParameters == 2)) {
    std::ostringstream memAddrStr;
    memAddrStr << "0x" << std::hex << record.ExceptionInformation[1];

    errorMsg << "The instruction at " << exAddrStr.str()
             << " referenced memory at " << memAddrStr.str() << ".";
    switch (record.ExceptionInformation[0]) {
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
  } else if ((record.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
             (record.NumberParameters == 3)) {
    std::ostringstream memAddrStr;
    memAddrStr << "0x" << std::hex << record.ExceptionInformation[1];

    std::ostringstream ntstatusStr;
    ntstatusStr << "0x" << std::hex << record.ExceptionInformation[2];

    errorMsg << "The instruction at " << exAddrStr.str()
             << " referenced memory at " << memAddrStr.str() << "."
             << " The required data was not placed into memory because of"
             << " an I/O error status of " << ntstatusStr.str() << ".";
    r["exception_message"] = errorMsg.str();
  }

  return Status::success();
}

Status logPIDAndTID(IDebugSystemObjects2* system, Row& r) {
  unsigned long type = 0;
  unsigned long procID = 0;
  unsigned long threadID = 0;

  if ((system->GetCurrentProcessSystemId(&procID) != S_OK) ||
      (system->GetCurrentThreadSystemId(&threadID) != S_OK)) {
    return Status(1);
  }

  r["pid"] = BIGINT(procID);
  r["tid"] = BIGINT(threadID);
  return Status::success();
}

Status logProcessUptime(IDebugSystemObjects2* system, Row& r) {
  unsigned long uptime = 0;
  if (system->GetCurrentProcessUpTime(&uptime) == S_OK) {
    r["process_uptime"] = BIGINT(uptime);
    return Status::success();
  }
  return Status(1);
}

Status logDumpTime(IDebugControl5* control, Row& r) {
  unsigned long epoch = 0;
  if (control->GetCurrentTimeDate(&epoch) != S_OK) {
    return Status(0);
  }

  std::time_t datetime = epoch;
  struct tm gmt;
  gmtime_s(&gmt, &datetime);
  std::stringstream dumpTimestamp;
  dumpTimestamp << std::put_time(&gmt, "%Y-%m-%d %H:%M:%S UTC");
  r["datetime"] = dumpTimestamp.str();
  return Status::success();
}

Status logOSVersion(IDebugControl5* control, Row& r) {
  unsigned long platformID;
  unsigned long majorVersion;
  unsigned long minorVersion;
  unsigned long buildNumber;

  if (control->GetSystemVersionValues(
          &platformID, &majorVersion, &minorVersion, nullptr, &buildNumber) ==
      S_OK) {
    r["major_version"] = INTEGER(majorVersion);
    r["minor_version"] = INTEGER(minorVersion);
    r["build_number"] = INTEGER(buildNumber);
    return Status::success();
  }
  return Status(1);
}

Status logDumpType(IDebugControl5* control, Row& r) {
  unsigned long flags = 0;
  if (control->GetDumpFormatFlags(&flags) != S_OK) {
    return Status(1);
  }

  std::vector<std::string> activeFlags;
  // Loop through MINIDUMP_TYPE flags and log the ones that are set
  for (auto const& flag : kMinidumpTypeFlags) {
    if (flags & flag.first) {
      activeFlags.push_back(flag.second);
    }
  }
  r["type"] = osquery::join(activeFlags, ",");
  return Status::success();
}

// Note: appears to only detect unmanaged stack frames.
// See http://blog.steveniemitz.com/building-a-mixed-mode-stack-walker-part-2/
Status logStackTrace(IDebugControl5* control, IDebugSymbols3* symbols, Row& r) {
  CONTEXT context = {0};
  unsigned long type = 0;
  unsigned long procID = 0;
  unsigned long threadID = 0;
  unsigned long contextSize = 0;
  unsigned long numFrames = 0;
  DEBUG_STACK_FRAME_EX stackFrames[kNumStackFramesToLog] = {0};

  if (control->GetStackTraceEx(
          0, 0, 0, stackFrames, kNumStackFramesToLog, &numFrames) != S_OK) {
    return Status(1);
  }

  // Then, log the stack frames
  std::vector<std::string> stackTraces;
  std::vector<char> name(512, 0x0);
  std::ostringstream stackTrace;
  for (unsigned long frame = 0; frame < numFrames; frame++) {
    unsigned long long offset = 0;

    if (symbols->GetNameByOffset(stackFrames[frame].InstructionOffset,
                                 name.data(),
                                 static_cast<unsigned long>(name.size() - 1),
                                 nullptr,
                                 &offset) == S_OK) {
      stackTrace << name.data() << "+0x" << std::hex << offset;
    }
    stackTrace << "(0x" << std::hex << stackFrames[frame].InstructionOffset;
    stackTrace << ")";
    stackTraces.push_back(stackTrace.str());
    name.clear();
    stackTrace.str("");
  }
  r["stack_trace"] = osquery::join(stackTraces, ",");
  return Status::success();
}

Status logRegisters(IDebugClient5* client,
                    IDebugControl5* control,
                    IDebugRegisters* registers,
                    IDebugAdvanced* advanced,
                    Row& r) {
  RegisterOutputCallbacks callback(&r);
  if (client->SetOutputCallbacks(&callback) != S_OK) {
    return Status(1);
  }

  // Attempt to set thread context from stored event (usually an exception)
  CONTEXT context = {0};
  unsigned long type = 0;
  unsigned long procID = 0;
  unsigned long threadID = 0;
  if (control->GetStoredEventInformation(&type,
                                         &procID,
                                         &threadID,
                                         &context,
                                         sizeof(context),
                                         nullptr,
                                         nullptr,
                                         0,
                                         nullptr) == S_OK) {
    advanced->SetThreadContext(&context, sizeof(context));
  }

  auto status = registers->OutputRegisters(DEBUG_OUTCTL_THIS_CLIENT,
                                           DEBUG_REGISTERS_DEFAULT);
  client->SetOutputCallbacks(nullptr);
  return (status == S_OK) ? Status() : Status(1);
}

Status logPEPathAndVersion(IDebugSymbols3* symbols, Row& r) {
  char pePath[MAX_PATH + 1] = {0};
  if (symbols->GetModuleNameString(
          DEBUG_MODNAME_IMAGE, 0, 0, pePath, MAX_PATH + 1, nullptr) == S_OK) {
    r["path"] = pePath;
  }

  VS_FIXEDFILEINFO version = {0};
  if (symbols->GetModuleVersionInformation(
          0, 0, "\\", &version, sizeof(version), nullptr) == S_OK) {
    std::ostringstream versionStr;
    versionStr << ((version.dwFileVersionMS >> 16) & 0xffff) << "."
               << ((version.dwFileVersionMS >> 0) & 0xffff) << "."
               << ((version.dwFileVersionLS >> 16) & 0xffff) << "."
               << ((version.dwFileVersionLS >> 0) & 0xffff);
    r["version"] = versionStr.str();
    return Status::success();
  }
  return Status(1);
}

Status logModulePath(IDebugSymbols3* symbols, Row& r) {
  std::istringstream converter(r["exception_address"]);
  unsigned long long exAddr;
  converter >> std::hex >> exAddr;
  if (converter.fail()) {
    return Status(1);
  }

  unsigned long modIndex = 0;
  char modPath[MAX_PATH + 1] = {0};
  if ((symbols->GetModuleByOffset(exAddr, 0, &modIndex, nullptr) == S_OK) &&
      (symbols->GetModuleNameString(
           DEBUG_MODNAME_IMAGE, modIndex, 0, modPath, MAX_PATH + 1, nullptr) ==
       S_OK)) {
    r["module"] = modPath;
    return Status::success();
  }
  return Status(1);
}

Status logPEBInfo(IDebugClient5* client,
                  IDebugControl5* control,
                  IDebugSymbols3* symbols,
                  IDebugSystemObjects2* system,
                  IDebugDataSpaces4* data,
                  Row& r) {
  // Get ntdll symbols
  symbols->Reload("/f ntdll.dll");
  unsigned long long ntdllBase = 0;
  if (symbols->GetModuleByModuleName("ntdll", 0, nullptr, &ntdllBase) != S_OK) {
    return Status(1);
  }

  // Get PEB address
  unsigned long long pebAddr = 0;
  if (system->GetCurrentProcessPeb(&pebAddr) != S_OK) {
    return Status(1);
  }

  // Get ProcessParameters offset in the PEB
  unsigned long pebTypeId = 0;
  unsigned long procParamsOffset = 0;
  if ((symbols->GetTypeId(ntdllBase, "_PEB", &pebTypeId) != S_OK) ||
      (symbols->GetFieldOffset(
           ntdllBase, pebTypeId, "ProcessParameters", &procParamsOffset) !=
       S_OK)) {
    return Status(1);
  }

  // Get address of ProcessParameters struct
  unsigned long long procParamsAddr = 0;
  if (data->ReadPointersVirtual(
          1, pebAddr + procParamsOffset, &procParamsAddr) != S_OK) {
    return Status(1);
  }

  // Get CurrentDirectory offset in ProcessParameters
  unsigned long procParamsTypeId = 0;
  unsigned long curDirOffset = 0;
  if ((symbols->GetTypeId(ntdllBase,
                          "_RTL_USER_PROCESS_PARAMETERS",
                          &procParamsTypeId) != S_OK) ||
      (symbols->GetFieldOffset(
           ntdllBase, procParamsTypeId, "CurrentDirectory", &curDirOffset) !=
       S_OK)) {
    return Status(1);
  }

  // Log CurrentDirectory
  unsigned long long curDirBufferAddr = 0;
  if (data->ReadPointersVirtual(
          1, procParamsAddr + curDirOffset + 0x8, &curDirBufferAddr) != S_OK) {
    return Status(1);
  }
  wchar_t curDir[MAX_PATH + 1] = {0};
  data->ReadUnicodeStringVirtualWide(
      curDirBufferAddr, sizeof(curDir), curDir, MAX_PATH + 1, nullptr);
  r["current_directory"] = wstringToString(curDir);

  // Get CommandLine offset in ProcessParameters
  unsigned long cmdLineOffset = 0;
  if (symbols->GetFieldOffset(
          ntdllBase, procParamsTypeId, "CommandLine", &cmdLineOffset) != S_OK) {
    return Status(1);
  }

  // Log CommandLine
  unsigned long long cmdLineBufferAddr = 0;
  if (data->ReadPointersVirtual(1,
                                procParamsAddr + cmdLineOffset + 0x8,
                                &cmdLineBufferAddr) != S_OK) {
    return Status(1);
  }
  wchar_t cmdLine[UNICODE_STRING_MAX_BYTES] = {0};
  data->ReadUnicodeStringVirtualWide(cmdLineBufferAddr,
                                     sizeof(cmdLine),
                                     cmdLine,
                                     UNICODE_STRING_MAX_BYTES,
                                     nullptr);
  r["command_line"] = wstringToString(cmdLine);

  // Get Environment offset in ProcessParameters
  unsigned long envOffset = 0;
  if (symbols->GetFieldOffset(
          ntdllBase, procParamsTypeId, "Environment", &envOffset) != S_OK) {
    return Status(1);
  }

  // Get Environment
  unsigned long long envBufferAddr = 0;
  if (data->ReadPointersVirtual(
          1, procParamsAddr + envOffset, &envBufferAddr) != S_OK) {
    return Status(1);
  }

  // Loop through environment variables and log those of interest
  // The environment variables are stored in the following format:
  // Var1=Value1\0Var2=Value2\0Var3=Value3\0 ... VarN=ValueN\0\0
  wchar_t env[UNICODE_STRING_MAX_BYTES] = {0};
  unsigned long bytesRead = 0;
  auto ret = data->ReadUnicodeStringVirtualWide(
      envBufferAddr, sizeof(env), env, UNICODE_STRING_MAX_BYTES, &bytesRead);
  while (ret == S_OK) {
    envBufferAddr += bytesRead;
    auto envVar = wstringToString(env);
    auto pos = envVar.find('=');
    auto varName = envVar.substr(0, pos);
    auto varValue = envVar.substr(pos + 1, envVar.length());

    if (varName == "COMPUTERNAME") {
      r["machine_name"] = varValue;
    } else if (varName == "USERNAME") {
      r["username"] = varValue;
    }

    ret = data->ReadUnicodeStringVirtualWide(
        envBufferAddr, sizeof(env), env, UNICODE_STRING_MAX_BYTES, &bytesRead);
  }

  return Status::success();
}

void debugEngineCleanup(IDebugClient5* client,
                        IDebugControl5* control,
                        IDebugSymbols3* symbols,
                        IDebugSystemObjects2* system,
                        IDebugDataSpaces4* data,
                        IDebugRegisters* registers,
                        IDebugAdvanced* advanced) {
  if (control != nullptr) {
    control->Release();
  }
  if (symbols != nullptr) {
    symbols->Release();
  }
  if (system != nullptr) {
    system->Release();
  }
  if (data != nullptr) {
    data->Release();
  }
  if (registers != nullptr) {
    registers->Release();
  }
  if (advanced != nullptr) {
    advanced->Release();
  }
  if (client != nullptr) {
    client->EndSession(DEBUG_END_PASSIVE);
    client->Release();
  }
  return;
}

void processDebugEngine(const std::string& fileName, Row& r) {
  const unsigned long kSymbolOptions =
      SYMOPT_CASE_INSENSITIVE & SYMOPT_UNDNAME & SYMOPT_LOAD_LINES &
      SYMOPT_OMAP_FIND_NEAREST & SYMOPT_LOAD_ANYTHING &
      SYMOPT_FAIL_CRITICAL_ERRORS & SYMOPT_AUTO_PUBLICS;

  IDebugClient5* client = nullptr;
  IDebugControl5* control = nullptr;
  IDebugSymbols3* symbols = nullptr;
  IDebugSystemObjects2* system = nullptr;
  IDebugDataSpaces4* data = nullptr;
  IDebugRegisters* registers = nullptr;
  IDebugAdvanced* advanced = nullptr;

  // Create debug interfaces
  if (DebugCreate(__uuidof(IDebugClient5), (void**)&client) != S_OK) {
    LOG(ERROR) << "DebugCreate failed while debugging crash dump: " << fileName;
    return;
  }
  if ((client->QueryInterface(__uuidof(IDebugControl5), (void**)&control) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugSymbols3), (void**)&symbols) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugSystemObjects2),
                              (void**)&system) != S_OK) ||
      (client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&data) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugRegisters), (void**)&registers) !=
       S_OK) ||
      (client->QueryInterface(__uuidof(IDebugAdvanced), (void**)&advanced) !=
       S_OK)) {
    LOG(ERROR) << "Failed to generate interfaces while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(
        client, control, symbols, system, data, registers, advanced);
  }

  // Initialize debug engine
  if ((symbols->SetSymbolPath(kSymbolPath.c_str()) != S_OK) ||
      (symbols->SetSymbolOptions(kSymbolOptions) != S_OK) ||
      (client->OpenDumpFile(fileName.c_str()) != S_OK) ||
      (control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)) {
    LOG(ERROR) << "Failed during initialization while debugging crash dump: "
               << fileName;
    return debugEngineCleanup(
        client, control, symbols, system, data, registers, advanced);
  }

  // Extract information from the minidump
  r["crash_path"] = fileName;
  logDumpType(control, r);
  logDumpTime(control, r);
  logProcessUptime(system, r);
  logPIDAndTID(system, r);
  logOSVersion(control, r);
  logExceptionInfo(control, r);
  logStackTrace(control, symbols, r);
  logPEPathAndVersion(symbols, r);
  logModulePath(symbols, r);
  logRegisters(client, control, registers, advanced, r);
  logPEBInfo(client, control, symbols, system, data, r);

  // Cleanup
  return debugEngineCleanup(
      client, control, symbols, system, data, registers, advanced);
}

QueryData genCrashLogs(QueryContext& context) {
  const std::string kDumpFileExtension = ".dmp";
  QueryData results;
  std::string dumpFolderLocation{""};

  // Query registry for crash dump folder
  std::string dumpFolderQuery =
      "SELECT data FROM registry WHERE path = \"" + kLocalDumpsRegKey + "\"";
  SQL dumpFolderResults(dumpFolderQuery);
  if (!dumpFolderResults.rows().empty()) {
    dumpFolderLocation = dumpFolderResults.rows()[0].at("data");
  } else {
    auto tempDumpLoc = getEnvVar("TMP");
    dumpFolderLocation = tempDumpLoc.is_initialized() ? *tempDumpLoc : "";
  }

  if (const auto expandedPath = expandEnvString(dumpFolderLocation)) {
    dumpFolderLocation = *expandedPath;
  }

  if (!fs::exists(dumpFolderLocation) ||
      !fs::is_directory(dumpFolderLocation)) {
    VLOG(1) << "No crash dump directory found";
    return results;
  }

  // Enumerate and process crash dumps
  std::vector<std::string> files;
  if (listFilesInDirectory(dumpFolderLocation, files)) {
    for (const auto& lf : files) {
      if (alg::iends_with(lf, kDumpFileExtension) && fs::is_regular_file(lf)) {
        Row r;
        processDebugEngine(lf, r);
        if (!r.empty()) {
          results.push_back(r);
        }
      }
    }
  }

  return results;
}
}
}
