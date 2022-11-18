/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <osquery/core/flags.h>
#include <osquery/events/windows/etw/etw_publisher_processes.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

FLAG(bool,
     enable_etw_process_events,
     false,
     "Enables the etw_process_events publisher");

// ETW Event publisher registration into the Osquery pub-sub framework
REGISTER_ETW_PUBLISHER(EtwPublisherProcesses, kEtwProcessPublisherName.c_str());

// Publisher constructor
EtwPublisherProcesses::EtwPublisherProcesses()
    : EtwPublisherBase(kEtwProcessPublisherName) {
  initializeHardVolumeConversions();
};

// There are multiple ETW providers being setup here. Events arriving from
// these providers will be aggregated in the post-processing phase.
Status EtwPublisherProcesses::setUp() {
  if (!FLAGS_enable_etw_process_events) {
    return Status::failure(kEtwProcessPublisherName +
                           " publisher disabled via configuration.");
  }
  // ETW Initialization logic
  const EtwProviderConfig::EtwBitmask processStartStopKeyword = 0x10;

  // Userspace ETW Provider configuration
  EtwProviderConfig userEtwProviderConfig;
  userEtwProviderConfig.setName("Microsoft-Windows-Kernel-Process");
  userEtwProviderConfig.setAnyBitmask(processStartStopKeyword);
  userEtwProviderConfig.setPreProcessor(ProviderPreProcessor);
  userEtwProviderConfig.setPostProcessor(getPostProcessorCallback());
  userEtwProviderConfig.addEventType(EtwEventType::ProcessStart);
  userEtwProviderConfig.addEventType(EtwEventType::ProcessStop);

  // Adding the provider to the ETW Engine
  Status userProviderAddStatus = EtwEngine().addProvider(userEtwProviderConfig);
  if (!userProviderAddStatus.ok()) {
    return userProviderAddStatus;
  }

  // Kernelspace ETW Provider configuration
  EtwProviderConfig kernelProviderCfg;
  kernelProviderCfg.setKernelProviderType(
      EtwProviderConfig::EtwKernelProviderType::Process);
  kernelProviderCfg.setPreProcessor(ProviderPreProcessor);
  kernelProviderCfg.setPostProcessor(getPostProcessorCallback());
  kernelProviderCfg.addEventType(EtwEventType::ProcessStart);
  kernelProviderCfg.addEventType(EtwEventType::ProcessStop);

  // Adding the provider to the ETW Engine
  Status kernelProviderAddStatus = EtwEngine().addProvider(kernelProviderCfg);
  if (!kernelProviderAddStatus.ok()) {
    return kernelProviderAddStatus;
  }

  return Status::success();
}

// Checking if given ETW event is coming from a kernel provider
static inline bool isKernelEvent(const EVENT_HEADER& header) {
  bool ret = false;

  // ETW events coming from kernel providers have this fields set to zero
  if ((header.EventDescriptor.Channel == 0) &&
      (header.EventDescriptor.Level == 0) &&
      (header.EventDescriptor.Task == 0)) {
    ret = true;
  }

  return ret;
}

// Callback to perform pre-processing logic
void EtwPublisherProcesses::ProviderPreProcessor(
    const EVENT_RECORD& rawEvent, const krabs::trace_context& traceCtx) {
  static const USHORT etwDefaultKernelID = 0;
  static const USHORT etwProcessStartID = 1;
  static const USHORT etwProcessStopID = 2;
  static const UCHAR etwExpectedKernelVersion = 4;
  static const UCHAR etwExpectedUserProcStartVersion = 3;

  // Helpers definition
  USHORT eventID = rawEvent.EventHeader.EventDescriptor.Id;
  UCHAR eventVersion = rawEvent.EventHeader.EventDescriptor.Version;

  if ((eventID != etwProcessStartID) && // Userspace Process-start event ID
      (eventID != etwProcessStartID) && // Userspace Process-stop event ID
      (eventID != etwDefaultKernelID)) { // Kernelspace default event ID
    return;
  }

  // ETW event schema parsing
  krabs::schema schema(rawEvent, traceCtx.schema_locator);
  krabs::parser parser(schema);

  // Internal ETW Event allocation - This event will be populated and dispatched
  std::shared_ptr<EtwEventData> newEvent = std::make_shared<EtwEventData>();
  if (newEvent == nullptr) {
    return;
  }

  // Parsing ETW Event payload based on its type
  bool eventShouldBeDispatched = false;
  if (isKernelEvent(rawEvent.EventHeader)) {
    UCHAR opcode = rawEvent.EventHeader.EventDescriptor.Opcode;

    // Sanity check on expected kernel events
    if ((opcode != etwProcessStartID) && (opcode != etwProcessStopID) &&
        (eventVersion != etwExpectedKernelVersion)) {
      return;
    }

    // Checking event opcode to determine if this is an event containing
    // process-start information
    if (opcode == etwProcessStartID) {
      newEvent->Header.Type = EtwEventType::ProcessStart;

      // Allocating proce-start specific payload
      auto procStartData = std::make_shared<EtwProcessStartData>();

      // Parsing event payload
      procStartData->Cmdline.assign(
          wstringToString(parser.parse<std::wstring>(L"CommandLine")));
      procStartData->Flags = parser.parse<uint32_t>(L"Flags");
      procStartData->ProcessId = parser.parse<uint32_t>(L"ProcessId");
      procStartData->ParentProcessId = parser.parse<uint32_t>(L"ParentId");
      procStartData->SessionId = parser.parse<uint32_t>(L"SessionId");
      krabs::sid userSID = parser.parse<krabs::sid>(L"UserSID");
      procStartData->UserSid.assign(userSID.sid_string);
      procStartData->KernelDataReady = true;
      newEvent->Payload = procStartData;

      eventShouldBeDispatched = true;

    } else if (opcode == etwProcessStopID) {
      // Checking event opcode to determine if this is an event containing
      // process-stop information

      // Event type
      newEvent->Header.Type = EtwEventType::ProcessStop;

      // Payload
      auto procStopData = std::make_shared<EtwProcessStopData>();
      procStopData->Cmdline.assign(
          wstringToString(parser.parse<std::wstring>(L"CommandLine")));
      procStopData->ExitCode = parser.parse<int32_t>(L"ExitStatus");
      procStopData->Flags = parser.parse<uint32_t>(L"Flags");
      procStopData->ImageName.assign(
          parser.parse<std::string>(L"ImageFileName"));
      procStopData->ProcessId = parser.parse<uint32_t>(L"ProcessId");
      procStopData->ParentProcessId = parser.parse<uint32_t>(L"ParentId");
      procStopData->SessionId = parser.parse<uint32_t>(L"SessionId");
      krabs::sid userSID = parser.parse<krabs::sid>(L"UserSID");
      procStopData->UserSid.assign(userSID.sid_string);
      newEvent->Payload = procStopData;

      eventShouldBeDispatched = true;
    }

  } else {
    // this is an ETW event coming from a userspace provider
    // so event ID needs to be checked
    if ((eventID == etwProcessStartID) &&
        (eventVersion == etwExpectedUserProcStartVersion)) {
      // Event type
      newEvent->Header.Type = EtwEventType::ProcessStart;

      // Payload
      EtwProcStartDataRef procStartData =
          std::make_shared<EtwProcessStartData>();
      procStartData->ImageName.assign(
          wstringToString(parser.parse<std::wstring>(L"ImageName")));
      procStartData->CreateTime = parser.parse<FILETIME>(L"CreateTime");
      krabs::sid mandatoryLabel = parser.parse<krabs::sid>(L"MandatoryLabel");
      procStartData->MandatoryLabelSid.assign(mandatoryLabel.sid_string);
      procStartData->ProcessId = parser.parse<uint32_t>(L"ProcessID");
      procStartData->ProcessSequenceNumber =
          parser.parse<uint64_t>(L"ProcessSequenceNumber");
      procStartData->ParentProcessId =
          parser.parse<uint32_t>(L"ParentProcessID");
      procStartData->ParentProcessSequenceNumber =
          parser.parse<uint64_t>(L"ParentProcessSequenceNumber");
      procStartData->TokenElevationType =
          parser.parse<uint32_t>(L"ProcessTokenElevationType");
      procStartData->TokenIsElevated =
          parser.parse<uint32_t>(L"ProcessTokenIsElevated");
      procStartData->UserDataReady = true;
      newEvent->Payload = std::move(procStartData);

      eventShouldBeDispatched = true;
    }
  }

  if (!eventShouldBeDispatched) {
    return;
  }

  // Raw Header update
  newEvent->Header.RawHeader = rawEvent.EventHeader;

  // Dispatch the event
  EtwController::instance().dispatchETWEvents(std::move(newEvent));
}

// Callback to perform post-processing logic
void EtwPublisherProcesses::ProviderPostProcessor(
    const EtwEventDataRef& eventData) {
  auto event_context = createEventContext();

  // Sanity check on event types that this callback will handle
  if ((eventData->Header.Type != EtwEventType::ProcessStart) &&
      (eventData->Header.Type != EtwEventType::ProcessStop)) {
    return;
  }

  // Payload update and event dispatch
  if (eventData->Header.Type == EtwEventType::ProcessStop) {
    // sanity check on variant type
    if (!std::holds_alternative<EtwProcStopDataRef>(eventData->Payload)) {
      return;
    }

    // sanity check on payload content
    auto procStopData = std::get<EtwProcStopDataRef>(eventData->Payload);
    if (procStopData == nullptr) {
      return;
    }

    // Event enrichment phase
    updateUserInfo(procStopData->UserSid, procStopData->UserName);

    // Event dispatch
    event_context->data = std::move(eventData);
    fire(event_context);

  } else if (eventData->Header.Type == EtwEventType::ProcessStart) {
    // There is event aggregation and enrichment being done for
    // EtwEventType::ProcessStart events. The logic here makes sure that
    // performs event aggregation first and then enrich the final event before
    // dispatching it.

    // sanity check on variant type
    if (!std::holds_alternative<EtwProcStartDataRef>(eventData->Payload)) {
      return;
    }

    // sanity check on payload content
    auto procStartData = std::get<EtwProcStartDataRef>(eventData->Payload);
    if (procStartData == nullptr) {
      return;
    }

    // This is the search key to be used on the cache of process start events
    std::uint64_t searchKey = (uint64_t)procStartData->ProcessId << 32 |
                              procStartData->ParentProcessId;

    // Access to the map iterator is required, tryTakeCopy cannot be used here.
    auto processCacheIt = processCache_.find(searchKey);
    if (processCacheIt == processCache_.end()) {
      // this event needs to be agreggated, so cache it for the time being
      if ((procStartData->CreateTime.dwHighDateTime == 0) &&
          (procStartData->CreateTime.dwLowDateTime == 0)) {
        GetSystemTimeAsFileTime(&procStartData->CreateTime);
      }
      processCache_.insert({searchKey, procStartData});
    } else {
      // A previous event was found on the cache, aggregate and dispatch it
      auto procStartCacheData = processCacheIt->second;
      if (procStartCacheData == nullptr) {
        return;
      }

      // Event Agreggation stage
      bool shouldDispatch = false;
      if ((procStartCacheData->KernelDataReady) &&
          (procStartData->UserDataReady)) {
        procStartData->Cmdline.assign(procStartCacheData->Cmdline);
        procStartData->Flags = procStartCacheData->Flags;
        procStartData->SessionId = procStartCacheData->SessionId;
        procStartData->UserSid.assign(procStartCacheData->UserSid);
        shouldDispatch = true;

      } else if ((procStartCacheData->UserDataReady) &&
                 (procStartData->KernelDataReady)) {
        procStartData->ImageName.assign(procStartCacheData->ImageName);
        procStartData->CreateTime = procStartCacheData->CreateTime;
        procStartData->MandatoryLabelSid.assign(
            procStartCacheData->MandatoryLabelSid);
        procStartData->ProcessSequenceNumber =
            procStartCacheData->ProcessSequenceNumber;
        procStartData->ParentProcessSequenceNumber =
            procStartCacheData->ParentProcessSequenceNumber;
        procStartData->TokenElevationType =
            procStartCacheData->TokenElevationType;
        procStartData->TokenIsElevated = procStartCacheData->TokenIsElevated;
        shouldDispatch = true;
      }

      if (shouldDispatch) {
        // Event is ready to be dispatched

        // Event enrichment phase
        updateHardVolumeWithLogicalDrive(procStartData);
        updateUserInfo(procStartData->UserSid, procStartData->UserName);
        updateTokenInfo(procStartData);

        // Event dispatch
        event_context->data = std::move(eventData);
        fire(event_context);

        // Remove it from the cache
        processCache_.erase(processCacheIt);

        // Houskeeping of expired entries
        cleanOldCacheEntries();
      }
    }
  }
}

void EtwPublisherProcesses::cleanOldCacheEntries() {
  // Time stamp value is expressed in 100 nanosecond units, this is about
  // 10000000 nanoseconds per second
  static constexpr LONGLONG expiredTime10secs = 10000000 * 10;

  if (processCache_.empty()) {
    return;
  }

  FILETIME currentFiletimeTimestamp{0};
  GetSystemTimeAsFileTime(&currentFiletimeTimestamp);

  ULARGE_INTEGER currentTimestamp{0};
  currentTimestamp.HighPart = currentFiletimeTimestamp.dwHighDateTime;
  currentTimestamp.LowPart = currentFiletimeTimestamp.dwLowDateTime;

  auto it = processCache_.begin();
  while (it != processCache_.end()) {
    ULARGE_INTEGER eventTimestamp{0};
    eventTimestamp.HighPart = it->second->CreateTime.dwHighDateTime;
    eventTimestamp.LowPart = it->second->CreateTime.dwLowDateTime;

    // check if event is still there after 10 secs
    if ((eventTimestamp.QuadPart + expiredTime10secs) <
        currentTimestamp.QuadPart) {
      // event expire and should be deleted
      processCache_.erase(it++);
    } else {
      ++it;
    }
  }
}

void EtwPublisherProcesses::initializeHardVolumeConversions() {
  const std::string validDriveLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for (auto& driveLetter : validDriveLetters) {
    std::string queryPath;
    queryPath.push_back(driveLetter);
    queryPath.push_back(':');

    char hardVolume[MAX_PATH + 1] = {0};
    if (QueryDosDeviceA(queryPath.c_str(), hardVolume, MAX_PATH)) {
      hardVolumeDrives_.insert({hardVolume, queryPath});
    }
  }
}

void EtwPublisherProcesses::updateHardVolumeWithLogicalDrive(
    EtwProcStartDataRef& eventData) {
  // Updating the hardvolume entries with logical volume data
  for (auto& [hardVolume, logicalDrive] : hardVolumeDrives_) {
    size_t pos = 0;
    if ((pos = eventData->ImageName.find(hardVolume, pos)) !=
        std::string::npos) {
      eventData->ImageName.replace(pos, hardVolume.length(), logicalDrive);
      break;
    }
  }
}

void EtwPublisherProcesses::updateUserInfo(const std::string& user_sid,
                                           std::string& username) {
  // Updating user information using gathered user SIDs as input
  auto usernameIt = usernamesBySIDs_.find(user_sid);
  if (usernameIt != usernamesBySIDs_.end()) {
    auto cachedUsername = usernameIt->second;
    username.assign(cachedUsername);
  } else {
    PSID pSid = nullptr;

    if ((!ConvertStringSidToSidA(user_sid.c_str(), &pSid)) ||
        (pSid == nullptr)) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({user_sid, ""});
      return;
    }

    char domainNameStr[MAX_PATH] = {0};
    DWORD domainNameSize = MAX_PATH;
    char userNameStr[MAX_PATH] = {0};
    DWORD userNameSize = MAX_PATH;
    SID_NAME_USE sidType = SID_NAME_USE::SidTypeInvalid;

    if ((!LookupAccountSidA(NULL,
                            pSid,
                            userNameStr,
                            &userNameSize,
                            domainNameStr,
                            &domainNameSize,
                            &sidType)) ||
        (strlen(domainNameStr) == 0) || (strlen(userNameStr) == 0) ||
        (sidType == SID_NAME_USE::SidTypeInvalid)) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({user_sid, ""});
      LocalFree(pSid);
      return;
    }

    LocalFree(pSid);

    username.append(domainNameStr);
    username.append("\\");
    username.append(userNameStr);

    usernamesBySIDs_.insert({user_sid, username});
  }
}

void EtwPublisherProcesses::updateTokenInfo(EtwProcStartDataRef& eventData) {
  // Updating token information with descriptive type
  switch (eventData->TokenElevationType) {
  case TOKEN_ELEVATION_TYPE::TokenElevationTypeDefault:
    eventData->TokenElevationTypeInfo.assign("TokenElevationTypeDefault");
    break;

  case TOKEN_ELEVATION_TYPE::TokenElevationTypeFull:
    eventData->TokenElevationTypeInfo.assign("TokenElevationTypeFull");
    break;

  case TOKEN_ELEVATION_TYPE::TokenElevationTypeLimited:
    eventData->TokenElevationTypeInfo.assign("TokenElevationTypeLimited");
    break;

  default:
    eventData->TokenElevationTypeInfo.assign("TokenElevationTypeInvalid");
  }
}

} // namespace osquery
