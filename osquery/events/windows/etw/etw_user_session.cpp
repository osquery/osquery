/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/windows/etw/etw_provider_config.h>
#include <osquery/events/windows/etw/etw_user_session.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/status/status.h>

namespace osquery {

HIDDEN_FLAG(
    uint32,
    etw_userspace_trace_buffer_size,
    kEventTraceBufferSize,
    "Kilobytes of memory allocated for the ETW userspace tracing session");

HIDDEN_FLAG(
    uint32,
    etw_userspace_trace_minimum_buffers,
    kEventTraceMinimumBuffers,
    "Minimum number of buffers reserved for the tracing session buffer pool");

HIDDEN_FLAG(
    uint32,
    etw_userspace_trace_maximum_buffers,
    kEventTraceMaximumBuffers,
    "Maximum number of buffers reserved for the tracing session buffer pool");

HIDDEN_FLAG(uint32,
            etw_userspace_trace_flush_timer,
            kEventTraceFlushTimer,
            "How often, in seconds, any non-empty trace buffers are flushed");

UserEtwSessionRunnable::UserEtwSessionRunnable(const std::string& runnableName)
    : InternalRunnable(runnableName) {
  initUserTraceSession(runnableName);
}

UserEtwSessionRunnable::~UserEtwSessionRunnable() {
  stop();

  if (userTraceSession_) {
    userTraceSession_.reset();
  }

  runningProviders_.clear();
}

Status UserEtwSessionRunnable::addProvider(
    const EtwProviderConfig& configData) {
  // Sanity check on input ETW Provider configuration data
  Status validProvider = configData.isValid();
  if (!validProvider.ok()) {
    return Status::failure("Invalid ETW provider configuration data: " +
                           validProvider.getMessage());
  }

  // Sanity check on trace session object
  if (!userTraceSession_) {
    return Status::failure("ETW User trace session is not initialized");
  }

  // User space provider instantiation
  UserProviderRef provider = std::make_shared<krabs::provider<>>(
      stringToWstring(configData.getName()));

  // Kernel level filtering on the provider trace session
  // Events that matches all of the bits will be received
  if (configData.isAllBitmaskSet()) {
    provider->all(configData.getAllBitmask().get());
  }

  // Kernel level filtering on the provider trace session
  // Events that matches at least one of the bits will be received
  if (configData.isAnyBitmaskSet()) {
    provider->any(configData.getAnyBitmask().get());
  }

  // Event Provider Loglevel
  if (configData.isLevelSet()) {
    provider->level(configData.getLevel().get());
  }

  // Provider specific flags
  if (configData.isTraceFlagsSet()) {
    provider->trace_flags(configData.getTraceFlags().get());
  }

  // Provider preprocessor callback is registered
  provider->add_on_event_callback(configData.getPreProcessor());

  // Pausing the trace event session to enable the new provider configuration
  pause();

  // Keeping a reference to the provider object
  runningProviders_.push_back(provider);

  // Enabling ETW provider

  userTraceSession_->enable(*provider);

  // Resume the trace session listening once provider is ready
  resume();

  return Status::success();
}

void UserEtwSessionRunnable::start() {
  std::unique_lock<std::mutex> lock(mutex_);
  if (userTraceSession_) {
    while (!endTraceSession_) {
      userTraceSession_->start();
      traceSessionStopped_ = true;

      if (!endTraceSession_) {
        condition_.wait(lock);
      }
    }
  }
}

void UserEtwSessionRunnable::stop() {
  if (userTraceSession_) {
    endTraceSession_ = true;
    userTraceSession_->stop();
  }
}

void UserEtwSessionRunnable::pause() {
  if (userTraceSession_) {
    userTraceSession_->stop();
    while (!traceSessionStopped_) {
      Sleep(500);
    }
    traceSessionStopped_ = false;
  }
}

void UserEtwSessionRunnable::resume() {
  if (userTraceSession_) {
    condition_.notify_one();
  }
}

void UserEtwSessionRunnable::initUserTraceSession(
    const std::string& sessionName) {
  if (sessionName.empty()) {
    return;
  }

  // stop trace session
  stopUserTraceSession(sessionName.c_str());

  // check if this can fail
  userTraceSession_ =
      std::make_shared<krabs::user_trace>(stringToWstring(sessionName));

  // Setting default trace session properties
  EVENT_TRACE_PROPERTIES session_properties = {0};
  session_properties.BufferSize = FLAGS_etw_userspace_trace_buffer_size;
  session_properties.MinimumBuffers = FLAGS_etw_userspace_trace_minimum_buffers;
  session_properties.MaximumBuffers = FLAGS_etw_userspace_trace_maximum_buffers;
  session_properties.FlushTimer = FLAGS_etw_userspace_trace_flush_timer;
  session_properties.LogFileMode = kEventTraceLogFileMode;
  userTraceSession_->set_trace_properties(&session_properties);
}

void UserEtwSessionRunnable::stopUserTraceSession(
    const std::string& sessionName) {
  if (sessionName.empty()) {
    return;
  }

  struct SessionData {
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR SessionName[MAX_PATH];
  };

  SessionData sessionInfo = {0};
  sessionInfo.Properties.Wnode.BufferSize =
      (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
  sessionInfo.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  sessionInfo.Properties.LoggerNameOffset =
      (ULONG)sizeof(EVENT_TRACE_PROPERTIES);

  /// Best effort to stop ongoing trace session
  /// return code is captured only for logging purposes
  ULONG retCtrl = ControlTraceA(NULL,
                                sessionName.c_str(),
                                &sessionInfo.Properties,
                                EVENT_TRACE_CONTROL_STOP);
  if (retCtrl != ERROR_SUCCESS && retCtrl != ERROR_WMI_INSTANCE_NOT_FOUND) {
    LOG(WARNING) << "ControlTrace() failed with error code " << retCtrl;
  }
}
} // namespace osquery