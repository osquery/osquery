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
 * @brief Subscription details for EtwPublisherDNS events.
 */
struct EtwDNSEventSubContext : public SubscriptionContext {
 private:
  friend class EtwPublisherDNS;
};

/**
 * @brief Event details for EtwPublisherDNS events.
 */
struct EtwDNSEventContext : public EventContext {
  EtwEventDataRef data;
};

using EtwDNSEventContextRef = std::shared_ptr<EtwDNSEventContext>;
using EtwDNSEventSubContextRef = std::shared_ptr<EtwDNSEventSubContext>;

/**
 * @brief Publisher Name
 */
const std::string kEtwDNSPublisherName = "etw_dns_publisher";

/**
 * @brief Implements an EtwPublisher that collects and
 * dispatches ETW events with process-start and process-stop OS information.
 */
class EtwPublisherDNS
    : public EtwPublisherBase,
      public EventPublisher<EtwDNSEventSubContext, EtwDNSEventContext> {
  /**
   * @brief Publisher constants
   */
  static const USHORT etwDefaultKernelID = 0;
  static const USHORT etwDNSStartID = 1;
  static const USHORT etwDNSStopID = 2;

  /**
   * @brief Supported User Start DNS Events versions
   */
  const enum class etwUserDNSStartVersion {
    Version0 = 0,
    Version1,
    Version2,
    Version3
  };

  /**
   * @brief Supported User Stop DNS Events versions
   */
  enum class etwUserDNSStopVersion { Version0 = 0, Version1, Version2 };

  /**
   * @brief Supported Kernel DNS Events versions
   */
  enum class etwKernelDNSVersion { Version3 = 3, Version4 };

  /**
   * @brief Publisher type declaration
   */
  DECLARE_PUBLISHER(kEtwDNSPublisherName);

 public:
  EtwPublisherDNS();

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

 private:
  using HardVolumeDriveCollection =
      std::unordered_map<std::string, std::string>;
  using UsernameBySIDCollection = std::unordered_map<std::string, std::string>;

  HardVolumeDriveCollection hardVolumeDrives_;
  UsernameBySIDCollection usernamesBySIDs_;
};

} // namespace osquery
