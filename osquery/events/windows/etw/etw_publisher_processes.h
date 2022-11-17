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

static const std::string kEtwProcessPublisherName = "etw_process_publisher";

/**
 * @brief EtwPublisherProcesses implements an EtwPublisher that collects and
 * dispatches ETW events with process-start and process-stop OS information.
 */
class EtwPublisherProcesses
    : public EtwPublisherBase,
      public EventPublisher<EtwProcEventSubContext, EtwProcessEventContext> {
  DECLARE_PUBLISHER(kEtwProcessPublisherName);

 public:
  EtwPublisherProcesses();

  /**
   * @brief Setup() is used to configure the ETW providers to listen, along with
   * its configuration parameters and processing callbacks.
   *
   * @return Status of the provider setup process.
   */
  Status setUp() override;

 private:
  /**
   * @brief It provides the c-function callback in charge of performing the pre
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
  static void ProviderPreProcessor(const EVENT_RECORD& rawEvent,
                                   const krabs::trace_context& traceCtx);

  /**
   * @brief It provides the std::function callback in charge of performing the
   * post processing logic. This logic is used to enrich, aggregate and modify
   * the event data before dispatching it to the event subscribers.
   */
  void ProviderPostProcessor(const EtwEventDataRef& data) override;

  /// Event post-processing helpers
  void cleanOldCacheEntries();
  void initializeHardVolumeConversions();
  void updateHardVolumeWithLogicalDrive(EtwProcStartDataRef& eventData);
  void updateTokenInfo(EtwProcStartDataRef& eventData);
  void updateUserInfo(const std::string& user_sid, std::string& username);

 private:
  std::unordered_map<std::uint64_t, EtwProcStartDataRef> processCache_;
  std::unordered_map<std::string, std::string> hardVolumeDrives_;
  std::unordered_map<std::string, std::string> usernamesBySIDs_;
};

} // namespace osquery
