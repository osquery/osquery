/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <variant>

#include <osquery/events/windows/etw/etw_krabs.h>

namespace osquery {

/**
 * @brief Process start event payload
 */
struct EtwProcessStartData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  /// Parent Process ID
  std::uint32_t ParentProcessId{0};

  /// Process Creation Time
  FILETIME CreateTime{0};

  /// Session ID
  std::uint32_t SessionId{0};

  /// Process Flags
  std::uint32_t Flags{0};

  /// Process Name
  std::string ImageName;

  /// Command Line
  std::string Cmdline;

  /// Mandatory Label SID
  std::string MandatoryLabelSid;

  /// User SID
  std::string UserSid;

  /// User Name
  std::string UserName;

  /// Token Elevation Type
  std::uint32_t TokenElevationType{0};

  /// Token Elevation Type Description
  std::string TokenElevationTypeInfo;

  /// Token IsElevated
  std::uint32_t TokenIsElevated{0};

  /// Process Sequence Number
  std::uint64_t ProcessSequenceNumber{0};

  /// Parent Process Sequence Number
  std::uint64_t ParentProcessSequenceNumber{0};

  /// Flag to indicate that kernel data has been gathered
  bool KernelDataReady{false};

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwProcStartDataRef = std::shared_ptr<EtwProcessStartData>;

/**
 * @brief Process stop event payload
 */
struct EtwProcessStopData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  /// Parent Process ID
  std::uint32_t ParentProcessId{0};

  /// Exit Code
  std::int32_t ExitCode{0};

  /// Process Flags
  std::uint32_t Flags{0};

  /// Process Name
  std::string ImageName;

  /// Session ID
  std::uint32_t SessionId{0};

  /// Command Line
  std::string Cmdline;

  /// User SID
  std::string UserSid;

  /// User Name
  std::string UserName;
};

using EtwProcStopDataRef = std::shared_ptr<EtwProcessStopData>;

/**
 * @brief ETW Event Payload
 */
using EtwPayloadVariant =
    std::variant<std::monostate, EtwProcStartDataRef, EtwProcStopDataRef>;

/**
 * @brief Event types
 * The event type is used to tag an ETW event to an specific data type that will
 * be used to dispatch events to different provider post processors
 */
enum class EtwEventType { Invalid, ProcessStart, ProcessStop };

/**
 * @brief Event Type string representation
 */
const auto kEtwEventTypeStrings = std::unordered_map<EtwEventType, std::string>{
    {EtwEventType::Invalid, "Invalid"},
    {EtwEventType::ProcessStart, "ProcessStart"},
    {EtwEventType::ProcessStop, "ProcessStop"}};

/**
 * @brief ETW Event Header
 */
struct EtwHeaderData final {
  /// ETW event header
  EVENT_HEADER RawHeader;

  // Event Type
  EtwEventType Type{EtwEventType::Invalid};

  // Event Type Info
  std::string TypeInfo;

  /// Process creation windows timestamp
  ULONGLONG WinTimestamp{0};

  /// Process creation unix timestamp
  LONGLONG UnixTimestamp{0};
};

/**
 * @brief ETW Event Data structure
 */
struct EtwEventData {
  EtwHeaderData Header;
  EtwPayloadVariant Payload;
};

using EtwEventDataRef = std::shared_ptr<EtwEventData>;
using EtwEventTypes = std::vector<EtwEventType>;

} // namespace osquery
