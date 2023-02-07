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
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/map_take.h>

namespace osquery {

FLAG(bool,
     enable_process_etw_events,
     false,
     "Enables the process_etw_events publisher");

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
  if (!FLAGS_enable_process_etw_events) {
    return Status::failure(kEtwProcessPublisherName +
                           " publisher disabled via configuration.");
  }
  // ETW Initialization logic
  const EtwProviderConfig::EtwBitmask processStartStopKeyword = 0x10;

  // Userspace ETW Provider configuration
  EtwProviderConfig userEtwProviderConfig;
  userEtwProviderConfig.setName("Microsoft-Windows-Kernel-Process");
  userEtwProviderConfig.setAnyBitmask(processStartStopKeyword);
  userEtwProviderConfig.setPreProcessor(getPreProcessorCallback());
  userEtwProviderConfig.setPostProcessor(getPostProcessorCallback());
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::ProcessStart);
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::ProcessStop);

  // Adding the provider to the ETW Engine
  Status userProviderAddStatus = EtwEngine().addProvider(userEtwProviderConfig);
  if (!userProviderAddStatus.ok()) {
    return userProviderAddStatus;
  }

  // Kernelspace ETW Provider configuration
  EtwProviderConfig kernelProviderCfg;
  kernelProviderCfg.setKernelProviderType(
      EtwProviderConfig::EtwKernelProviderType::Process);
  kernelProviderCfg.setPreProcessor(getPreProcessorCallback());
  kernelProviderCfg.setPostProcessor(getPostProcessorCallback());
  kernelProviderCfg.addEventTypeToHandle(EtwEventType::ProcessStart);
  kernelProviderCfg.addEventTypeToHandle(EtwEventType::ProcessStop);

  // Adding the provider to the ETW Engine
  Status kernelProviderAddStatus = EtwEngine().addProvider(kernelProviderCfg);
  if (!kernelProviderAddStatus.ok()) {
    return kernelProviderAddStatus;
  }

  return Status::success();
}

// Callback to perform pre-processing logic
void EtwPublisherProcesses::providerPreProcessor(
    const EVENT_RECORD& rawEvent, const krabs::trace_context& traceCtx) {
  // Helper accessors for userspace events
  const EVENT_HEADER& eventHeader = rawEvent.EventHeader;
  const unsigned int eventVersion = eventHeader.EventDescriptor.Version;

  // Checking if new event is a supported one
  if (!isSupportedEvent(eventHeader)) {
    return;
  }

  // ETW event schema parsing
  krabs::schema schema(rawEvent, traceCtx.schema_locator);
  krabs::parser parser(schema);

  // Internal ETW Event allocation - This event will be populated and dispatched
  std::shared_ptr<EtwEventData> newEvent = std::make_shared<EtwEventData>();
  if (newEvent == nullptr) {
    LOG(WARNING) << "Cannot allocate a new EtwEventData event";
    return;
  }

  // Parsing ETW Event payload based on its type
  bool eventShouldBeDispatched = false;
  if (isSupportedKernelEvent(eventHeader)) {
    // This is an event arriving from the ETW kernel provider!

    // Opcode == Event ID
    UCHAR opcode = eventHeader.EventDescriptor.Opcode;

    if (opcode == etwProcessStartID) {
      // Checking event opcode to determine if this is an event containing
      // process-start information

      // Event type initialization
      newEvent->Header.Type = EtwEventType::ProcessStart;

      // Allocating process-start specific payload
      auto procStartData = std::make_shared<EtwProcessStartData>();
      if (!procStartData) {
        LOG(WARNING) << "Cannot allocate a new EtwProcessStartData event";
        return;
      }

      // Parsing event payload
      procStartData->ProcessId = parser.parse<uint32_t>(L"ProcessId");
      procStartData->ParentProcessId = parser.parse<uint32_t>(L"ParentId");
      procStartData->SessionId = parser.parse<uint32_t>(L"SessionId");
      krabs::sid userSID = parser.parse<krabs::sid>(L"UserSID");
      procStartData->UserSid.assign(userSID.sid_string);

      if (eventVersion ==
          static_cast<unsigned int>(etwKernelProcVersion::Version4)) {
        procStartData->Cmdline.assign(
            wstringToString(parser.parse<std::wstring>(L"CommandLine")));
        procStartData->Flags = parser.parse<uint32_t>(L"Flags");
      }

      procStartData->KernelDataReady = true;
      newEvent->Payload = procStartData;

      eventShouldBeDispatched = true;

    } else if (opcode == etwProcessStopID) {
      // Checking event opcode to determine if this is an event containing
      // process-stop information

      // Event type initialization
      newEvent->Header.Type = EtwEventType::ProcessStop;

      // Allocating process-stop specific payload
      auto procStopData = std::make_shared<EtwProcessStopData>();
      if (!procStopData) {
        LOG(WARNING) << "Cannot allocate a new EtwProcessStopData event";
        return;
      }

      procStopData->ProcessId = parser.parse<uint32_t>(L"ProcessId");
      procStopData->ParentProcessId = parser.parse<uint32_t>(L"ParentId");
      procStopData->SessionId = parser.parse<uint32_t>(L"SessionId");
      krabs::sid userSID = parser.parse<krabs::sid>(L"UserSID");
      procStopData->UserSid.assign(userSID.sid_string);

      if (eventVersion ==
          static_cast<unsigned int>(etwKernelProcVersion::Version4)) {
        procStopData->Cmdline.assign(
            wstringToString(parser.parse<std::wstring>(L"CommandLine")));
        procStopData->ExitCode = parser.parse<int32_t>(L"ExitStatus");
        procStopData->Flags = parser.parse<uint32_t>(L"Flags");
        procStopData->ImageName.assign(
            parser.parse<std::string>(L"ImageFileName"));
      }

      newEvent->Payload = procStopData;

      eventShouldBeDispatched = true;
    }

  } else {
    // This is an ETW event coming from a userspace provider

    if (isSupportedUserProcessStartEvent(eventHeader)) {
      // Event type initialization
      newEvent->Header.Type = EtwEventType::ProcessStart;

      // Allocating process-start specific payload
      EtwProcStartDataRef procStartData =
          std::make_shared<EtwProcessStartData>();
      if (!procStartData) {
        LOG(WARNING) << "Cannot allocate a new EtwProcessStartData event";
        return;
      }

      procStartData->ProcessId = parser.parse<uint32_t>(L"ProcessID");
      procStartData->CreateTime = parser.parse<FILETIME>(L"CreateTime");
      procStartData->ParentProcessId =
          parser.parse<uint32_t>(L"ParentProcessID");
      procStartData->SessionId = parser.parse<uint32_t>(L"SessionID");
      procStartData->ImageName.assign(
          wstringToString(parser.parse<std::wstring>(L"ImageName")));

      if (eventVersion ==
              static_cast<unsigned int>(etwUserProcStartVersion::Version1) ||
          eventVersion ==
              static_cast<unsigned int>(etwUserProcStartVersion::Version2)) {
        procStartData->Flags = parser.parse<uint32_t>(L"Flags");

      } else if (eventVersion ==
                 static_cast<unsigned int>(etwUserProcStartVersion::Version3)) {
        procStartData->Flags = parser.parse<uint32_t>(L"Flags");
        krabs::sid mandatoryLabel = parser.parse<krabs::sid>(L"MandatoryLabel");
        procStartData->MandatoryLabelSid.assign(mandatoryLabel.sid_string);
        procStartData->ProcessSequenceNumber =
            parser.parse<uint64_t>(L"ProcessSequenceNumber");
        procStartData->ParentProcessSequenceNumber =
            parser.parse<uint64_t>(L"ParentProcessSequenceNumber");
        procStartData->TokenElevationType =
            parser.parse<uint32_t>(L"ProcessTokenElevationType");
        procStartData->TokenIsElevated =
            parser.parse<uint32_t>(L"ProcessTokenIsElevated");
      }

      procStartData->UserDataReady = true;
      newEvent->Payload = std::move(procStartData);

      eventShouldBeDispatched = true;
    }
  }

  // Returning if event should not be sent for post processing
  if (!eventShouldBeDispatched) {
    return;
  }

  // Raw Header update
  newEvent->Header.RawHeader = rawEvent.EventHeader;

  // Dispatch the event
  EtwController::instance().dispatchETWEvents(std::move(newEvent));
}

// Callback to perform post-processing logic
void EtwPublisherProcesses::providerPostProcessor(
    const EtwEventDataRef& eventData) {
  auto event_context = createEventContext();

  // Sanity check on event types that this callback will handle
  if (eventData->Header.Type != EtwEventType::ProcessStart &&
      eventData->Header.Type != EtwEventType::ProcessStop) {
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
    updateImagePath(procStopData->ProcessId,
                    procStopData->ParentProcessId,
                    procStopData->ImageName);

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
    std::uint64_t searchKey = getComposedKey(procStartData->ProcessId,
                                             procStartData->ParentProcessId);

    // Access to the map iterator is required, tryTakeCopy cannot be used here.
    auto processCacheIt = processStartAggregationCache_.find(searchKey);
    if (processCacheIt == processStartAggregationCache_.end()) {
      // this event needs to be agreggated, so cache it for the time being
      if (procStartData->CreateTime.dwHighDateTime == 0 &&
          procStartData->CreateTime.dwLowDateTime == 0) {
        GetSystemTimeAsFileTime(&procStartData->CreateTime);
      }
      processStartAggregationCache_.insert({searchKey, procStartData});
    } else {
      // A previous event was found on the cache, aggregate and dispatch it
      auto procStartCacheData = processCacheIt->second;
      if (procStartCacheData == nullptr) {
        return;
      }

      // Event Agreggation stage
      bool shouldDispatch = false;
      if (procStartCacheData->KernelDataReady && procStartData->UserDataReady) {
        procStartData->Cmdline.assign(procStartCacheData->Cmdline);
        procStartData->Flags = procStartCacheData->Flags;
        procStartData->SessionId = procStartCacheData->SessionId;
        procStartData->UserSid.assign(procStartCacheData->UserSid);
        procStartData->ProcessId = procStartCacheData->ProcessId;
        procStartData->ParentProcessId = procStartCacheData->ParentProcessId;

        shouldDispatch = true;

      } else if (procStartCacheData->UserDataReady &&
                 procStartData->KernelDataReady) {
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
        updateHardVolumeWithLogicalDrive(procStartData->ImageName);
        updateUserInfo(procStartData->UserSid, procStartData->UserName);
        updateTokenInfo(procStartData->TokenElevationType,
                        procStartData->TokenElevationTypeInfo);

        // Event dispatch
        event_context->data = std::move(eventData);
        fire(event_context);

        // Remove it from the process start aggregation cache
        processStartAggregationCache_.erase(processCacheIt);

        // Houskeeping of expired aggregation cache entries
        cleanOldAggregationCacheEntries();

        // Caching image full path
        processImageCache_.insert({searchKey, procStartData->ImageName});
      }
    }
  }
}

void EtwPublisherProcesses::initializeHardVolumeConversions() {
  const auto& validDriveLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for (const auto& driveLetter : validDriveLetters) {
    std::string queryPath;
    queryPath.push_back(driveLetter);
    queryPath.push_back(':');

    char hardVolume[MAX_PATH + 1] = {0};
    if (QueryDosDeviceA(queryPath.c_str(), hardVolume, MAX_PATH)) {
      hardVolumeDrives_.insert({hardVolume, queryPath});
    }
  }
}

void EtwPublisherProcesses::cleanOldAggregationCacheEntries() {
  // Time stamp value is expressed in 100 nanosecond units, this is about
  // 10000000 nanoseconds per second
  static constexpr LONGLONG expiredTime10secs = 10000000 * 10;

  if (processStartAggregationCache_.empty()) {
    return;
  }

  FILETIME currentFiletimeTimestamp{0};
  GetSystemTimeAsFileTime(&currentFiletimeTimestamp);

  ULARGE_INTEGER currentTimestamp{0};
  currentTimestamp.HighPart = currentFiletimeTimestamp.dwHighDateTime;
  currentTimestamp.LowPart = currentFiletimeTimestamp.dwLowDateTime;

  auto it = processStartAggregationCache_.begin();
  while (it != processStartAggregationCache_.end()) {
    ULARGE_INTEGER eventTimestamp{0};
    eventTimestamp.HighPart = it->second->CreateTime.dwHighDateTime;
    eventTimestamp.LowPart = it->second->CreateTime.dwLowDateTime;

    // check if event is still there after 10 secs
    if ((eventTimestamp.QuadPart + expiredTime10secs) <
        currentTimestamp.QuadPart) {
      // event expire and should be deleted
      processStartAggregationCache_.erase(it);
    }

    ++it;
  }
}

void EtwPublisherProcesses::updateHardVolumeWithLogicalDrive(
    std::string& path) {
  // Updating the hardvolume entries with logical volume data
  for (const auto& [hardVolume, logicalDrive] : hardVolumeDrives_) {
    size_t pos = 0;
    if ((pos = path.find(hardVolume, pos)) != std::string::npos) {
      path.replace(pos, hardVolume.length(), logicalDrive);
      break;
    }
  }
}

void EtwPublisherProcesses::updateUserInfo(const std::string& userSid,
                                           std::string& username) {
  // Updating user information using gathered user SIDs as input
  auto usernameIt = usernamesBySIDs_.find(userSid);
  if (usernameIt != usernamesBySIDs_.end()) {
    auto cachedUsername = usernameIt->second;
    username.assign(cachedUsername);
  } else {
    PSID pSid = nullptr;

    if (!ConvertStringSidToSidA(userSid.c_str(), &pSid) || pSid == nullptr) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      return;
    }

    std::vector<char> domainNameStr(MAX_PATH - 1, 0x0);
    std::vector<char> userNameStr(MAX_PATH - 1, 0x0);
    DWORD domainNameSize = MAX_PATH;
    DWORD userNameSize = MAX_PATH;
    SID_NAME_USE sidType = SID_NAME_USE::SidTypeInvalid;

    if (!LookupAccountSidA(NULL,
                           pSid,
                           userNameStr.data(),
                           &userNameSize,
                           domainNameStr.data(),
                           &domainNameSize,
                           &sidType) ||
        strlen(domainNameStr.data()) == 0 ||
        strlen(domainNameStr.data()) >= MAX_PATH ||
        strlen(userNameStr.data()) == 0 ||
        strlen(userNameStr.data()) >= MAX_PATH ||
        sidType == SID_NAME_USE::SidTypeInvalid) {
      // Inserting empty username to avoid the lookup logic to be called again
      usernamesBySIDs_.insert({userSid, ""});
      LocalFree(pSid);
      return;
    }

    LocalFree(pSid);

    username.append(domainNameStr.data());
    username.append("\\");
    username.append(userNameStr.data());

    usernamesBySIDs_.insert({userSid, username});
  }
}

void EtwPublisherProcesses::updateImagePath(const std::uint64_t& key1,
                                            const std::uint64_t& key2,
                                            std::string& imagePath) {
  // This is the search key to be used on the cache of process start events
  std::uint64_t searchKey = getComposedKey(key1, key2);

  // Event specific post processing callback logic
  imagePath = tryTake(processImageCache_, searchKey).takeOr(imagePath);
}

void EtwPublisherProcesses::updateTokenInfo(const std::uint32_t& tokenType,
                                            std::string& tokenInfo) {
  // Updating token information with descriptive type
  switch (tokenType) {
  case TOKEN_ELEVATION_TYPE::TokenElevationTypeDefault: {
    tokenInfo.assign("TokenElevationTypeDefault");
    break;
  }

  case TOKEN_ELEVATION_TYPE::TokenElevationTypeFull: {
    tokenInfo.assign("TokenElevationTypeFull");
    break;
  }

  case TOKEN_ELEVATION_TYPE::TokenElevationTypeLimited: {
    tokenInfo.assign("TokenElevationTypeLimited");
    break;
  }

  default:
    tokenInfo.assign("TokenElevationTypeInvalid");
  }
}

// Checking if given ETW event is a supported kernel event
bool EtwPublisherProcesses::isSupportedKernelEvent(const EVENT_HEADER& header) {
  // ETW events coming from kernel providers have this fields set to zero
  return (header.EventDescriptor.Channel == 0 &&
          header.EventDescriptor.Level == 0 &&
          header.EventDescriptor.Task == 0 &&
          (header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwKernelProcVersion::Version3) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwKernelProcVersion::Version4)));
}

// Checking if given ETW event is a supported userspace process start event
bool EtwPublisherProcesses::isSupportedUserProcessStartEvent(
    const EVENT_HEADER& header) {
  return (header.EventDescriptor.Id == etwProcessStartID &&
          (header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStartVersion::Version0) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStartVersion::Version1) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStartVersion::Version2) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStartVersion::Version3)));
}

// Checking if given ETW event ID is supported by preprocessor logic
bool EtwPublisherProcesses::isSupportedEvent(const EVENT_HEADER& header) {
  return (isSupportedKernelEvent(header) ||
          isSupportedUserProcessStartEvent(header) ||
          isSupportedUserProcessStopEvent(header));
}

// Checking if given ETW event is a supported userspace process stop event
bool EtwPublisherProcesses::isSupportedUserProcessStopEvent(
    const EVENT_HEADER& header) {
  return (header.EventDescriptor.Id == etwProcessStopID &&
          (header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStopVersion::Version0) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStopVersion::Version1) ||
           header.EventDescriptor.Version ==
               static_cast<UCHAR>(etwUserProcStopVersion::Version2)));
}

// Get uint64 composed kit
std::uint64_t EtwPublisherProcesses::getComposedKey(const std::uint64_t& key1,
                                                    const std::uint64_t& key2) {
  return static_cast<std::uint64_t>(static_cast<std::uint64_t>(key1) << 32 |
                                    key2);
}

} // namespace osquery
