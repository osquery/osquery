/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/etw/etw_controller.h>
#include <osquery/events/windows/etw/etw_provider_config.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

#define REGISTER_ETW_PUBLISHER(class_name, plugin_name)                        \
  REGISTER(class_name, "event_publisher", plugin_name)

#define REGISTER_ETW_SUBSCRIBER(class_name, plugin_name)                       \
  REGISTER(class_name, "event_subscriber", plugin_name)

#define getPreProcessorCallback()                                              \
  [](const EVENT_RECORD& rawEvent, const krabs::trace_context& traceCtx) {     \
    try {                                                                      \
      providerPreProcessor(rawEvent, traceCtx);                                \
    } catch (const std::exception& error) {                                    \
      LOG(ERROR) << "Exception error while parsing Event ID "                  \
                 << rawEvent.EventHeader.EventDescriptor.Id                    \
                 << " from ETW provider that starts with 0x" << std::hex       \
                 << rawEvent.EventHeader.ProviderId.Data1                      \
                 << " - Error is: " << error.what();                           \
    } catch (...) {                                                            \
    }                                                                          \
  } // namespace osquery

/**
 * @brief Abstracts the EventPublisher publisher functionality by exposing
 * only what's needed to deal with ETW event collection and dispatching. In
 * addition, this class provides means to interact with ETW events, by accessing
 * the ETW engine and implementing pre-process and post-process event callbacks.
 */
class EtwPublisherBase {
 public:
  EtwPublisherBase(const std::string& name);

  virtual ~EtwPublisherBase() = default;

  EtwController& EtwEngine();

  /**
   * @brief Allow the dispatcher to know that a running thread is not required
   * for this event publisher.
   */
  Status run();

  /**
   * @brief Returns a lambda instance that wraps the access to the post
   * processor callback defined in the publisher.
   */
  std::function<void(const EtwEventDataRef&)> getPostProcessorCallback();

 private:
  /**
   * @brief Abstract method that has to be implemented in the ETW publisher
   */
  virtual void providerPostProcessor(const EtwEventDataRef& data) = 0;

  /**
   * @brief Reference to the global ETW Controller instance
   */
  EtwController& etwController_{EtwController::instance()};

  /**
   * @brief Provider name
   */
  std::string name_;
};

} // namespace osquery
