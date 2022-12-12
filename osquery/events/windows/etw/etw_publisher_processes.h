/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/windows/etw/etw_publisher.h>

namespace osquery {

/**
 * @brief Subscriptioning details for EtwPublisherProcesses events.
 */
struct EtwProcEventSubContext : public SubscriptionContext {
 private:
  friend class EtwPublisherProcesses;
};

/**
 * @brief Event details for EtwPublisherProcesses events.
 */
struct EtwProcessEventContext : public EventContext {
  EtwEventDataRef data;
};

using EtwProcessEventContextRef = std::shared_ptr<EtwProcessEventContext>;
using EtwProcEventSubContextRef = std::shared_ptr<EtwProcEventSubContext>;

/**
 * @brief Publisher Name
 */
const std::string kEtwProcessPublisherName = "etw_process_publisher";

/**
 * @brief Implements an EtwPublisher that collects and
 * dispatches ETW events with process-start and process-stop OS information.
 */
class EtwPublisherProcesses
    : public EtwPublisherBase,
      public EventPublisher<EtwProcEventSubContext, EtwProcessEventContext> {
  /**
   * @brief Publisher constants
   */
  static const USHORT etwDefaultKernelID = 0;
  static const USHORT etwProcessStartID = 1;
  static const USHORT etwProcessStopID = 2;

  /**
   * @brief Supported User Start Process Events versions
   */
  const enum class etwUserProcStartVersion {
    Version0 = 0,
    Version1,
    Version2,
    Version3
  };

  /**
   * @brief Supported User Stop Process Events versions
   */
  enum class etwUserProcStopVersion { Version0 = 0, Version1, Version2 };

  /**
   * @brief Supported Kernel Process Events versions
   */
  enum class etwKernelProcVersion { Version3 = 3, Version4 };

  /**
   * @brief Publisher type declaration
   */
  DECLARE_PUBLISHER(kEtwProcessPublisherName);

 public:
  EtwPublisherProcesses();

  /**
   * @brief Used to configure the ETW providers to listen, along with
   * its configuration parameters and processing callbacks.
   *
   * @return Status of the provider setup process.
   */
  Status setUp() override;

 private:
  /**
   * @brief Provides the c-function callback in charge of performing the pre
   * processing logic. This is the entry point for the event arriving from the
   * ETW OS interface. This callback gets called from the OS for every new ETW
   * event. There should be lightweight logic here, with no significant
   * performance implications.
   *
   * @param rawEvent is the RAW ETW event obtained from OS ETW provider. It
   * comprises an EVENT_HEADER common to all ETW providers and a UserData field
   * with provider-specific content.
   * https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
   *
   * @param traceCtx This is a helper class that it is used to parse the ETW
   * event manifest when needed.
   */
  static void providerPreProcessor(const EVENT_RECORD& rawEvent,
                                   const krabs::trace_context& traceCtx);

  /**
   * @brief Provides the std::function callback in charge of performing the
   * post processing logic. This logic is used to enrich, aggregate and modify
   * the event data before dispatching it to the event subscribers.
   */
  void providerPostProcessor(const EtwEventDataRef& data) override;

  /// Event post-processing helpers
  void initializeHardVolumeConversions();
  void cleanOldAggregationCacheEntries();
  void updateHardVolumeWithLogicalDrive(std::string& path);
  void updateTokenInfo(const std::uint32_t& tokenType, std::string& tokenInfo);
  void updateUserInfo(const std::string& userSid, std::string& username);
  void updateImagePath(const std::uint64_t& key1,
                       const std::uint64_t& key2,
                       std::string& imagePath);
  static inline bool isSupportedEvent(const EVENT_HEADER& header);
  static inline bool isKernelEvent(const EVENT_HEADER& header);
  static inline bool isSupportedKernelEvent(const EVENT_HEADER& header);
  static inline bool isSupportedUserProcessStartEvent(
      const EVENT_HEADER& header);
  static inline bool isSupportedUserProcessStopEvent(
      const EVENT_HEADER& header);
  static inline std::uint64_t getComposedKey(const std::uint64_t& key1,
                                             const std::uint64_t& key2);

 private:
  using ProcessStartCacheCollection =
      std::unordered_map<std::uint64_t, EtwProcStartDataRef>;
  using ProcessImageCacheCollection =
      std::unordered_map<std::uint64_t, std::string>;
  using HardVolumeDriveCollection =
      std::unordered_map<std::string, std::string>;
  using UsernameBySIDCollection = std::unordered_map<std::string, std::string>;

  ProcessStartCacheCollection processStartAggregationCache_;
  ProcessImageCacheCollection processImageCache_;
  HardVolumeDriveCollection hardVolumeDrives_;
  UsernameBySIDCollection usernamesBySIDs_;
};

} // namespace osquery
