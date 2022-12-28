/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/windows/etw/etw_kernel_session.h>
#include <osquery/events/windows/etw/etw_provider_config.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/status/status.h>

namespace osquery {

HIDDEN_FLAG(
    uint32,
    etw_kernel_trace_buffer_size,
    kEventTraceBufferSize,
    "Kilobytes of memory allocated for the ETW kernelspace tracing session");

HIDDEN_FLAG(
    uint32,
    etw_kernel_trace_minimum_buffers,
    kEventTraceMinimumBuffers,
    "Minimum number of buffers reserved for the tracing session buffer pool");

HIDDEN_FLAG(
    uint32,
    etw_kernel_trace_maximum_buffers,
    kEventTraceMaximumBuffers,
    "Maximum number of buffers reserved for the tracing session buffer pool");

HIDDEN_FLAG(uint32,
            etw_kernel_trace_flush_timer,
            kEventTraceFlushTimer,
            "How often, in seconds, any non-empty trace buffers are flushed");

KernelEtwSessionRunnable::KernelEtwSessionRunnable(
    const std::string& runnableName)
    : InternalRunnable(runnableName) {
  initKernelTraceSession(runnableName);
}

KernelEtwSessionRunnable::~KernelEtwSessionRunnable() {
  stop();

  if (kernelTraceSession_) {
    kernelTraceSession_.reset();
  }
}

Status KernelEtwSessionRunnable::addProvider(
    const EtwProviderConfig& configData) {
  // Sanity check on input ETW Provider configuration data
  Status validProvider = configData.isValid();
  if (!validProvider.ok()) {
    return Status::failure("Invalid ETW provider configuration data: " +
                           validProvider.getMessage());
  }

  // Sanity check on trace session object
  if (!kernelTraceSession_) {
    return Status::failure("ETW kernel trace session is not initialized");
  }

  KernelProviderRef kernelProvider{nullptr};

  // Supported kernel providers instantiation
  EtwProviderConfig::EtwKernelProviderType kProviderType =
      configData.getKernelProviderType();

  switch (kProviderType) {
  case EtwProviderConfig::EtwKernelProviderType::File: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/fileio
    kernelProvider = std::make_shared<krabs::kernel::file_io_provider>();
  } break;

  case EtwProviderConfig::EtwKernelProviderType::ImageLoad: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/image-load
    kernelProvider = std::make_shared<krabs::kernel::image_load_provider>();
  } break;

  case EtwProviderConfig::EtwKernelProviderType::Network: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/tcpip
    kernelProvider = std::make_shared<krabs::kernel::network_tcpip_provider>();
  } break;

  case EtwProviderConfig::EtwKernelProviderType::Process: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/process
    kernelProvider = std::make_shared<krabs::kernel::process_provider>();
  } break;

  case EtwProviderConfig::EtwKernelProviderType::Registry: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/registry
    kernelProvider = std::make_shared<krabs::kernel::registry_provider>();
  } break;

  case EtwProviderConfig::EtwKernelProviderType::ObjectManager: {
    // https://learn.microsoft.com/en-us/windows/win32/etw/obtrace
    kernelProvider = std::make_shared<krabs::kernel::object_manager_provider>();
  } break;

  default:
    return Status::failure("Unsupported kernel provider was provided.");
  }

  if (kernelProvider == nullptr) {
    return Status::failure("There was a problem with given kernel provider.");
  }

  // Provider preprocessor callback is registered
  kernelProvider->add_on_event_callback(configData.getPreProcessor());

  // Pausing the trace event session to enable the new provider configuration
  pause();
  runningProviders_.push_back(kernelProvider);
  kernelTraceSession_->enable(*kernelProvider);

  // Resume the trace session listening once provider is ready
  resume();

  return Status::success();
}

void KernelEtwSessionRunnable::start() {
  std::unique_lock<std::mutex> lock(mutex_);
  if (kernelTraceSession_) {
    while (!endTraceSession_) {
      kernelTraceSession_->start();
      traceSessionStopped_ = true;

      if (!endTraceSession_) {
        condition_.wait(lock);
      }
    }
  }
}

void KernelEtwSessionRunnable::stop() {
  if (kernelTraceSession_) {
    endTraceSession_ = true;
    kernelTraceSession_->stop();
  }
}

void KernelEtwSessionRunnable::pause() {
  if (kernelTraceSession_) {
    kernelTraceSession_->stop();
    while (!traceSessionStopped_) {
      Sleep(500);
    }
    traceSessionStopped_ = false;
  }
}

void KernelEtwSessionRunnable::resume() {
  if (kernelTraceSession_) {
    condition_.notify_one();
  }
}

void KernelEtwSessionRunnable::initKernelTraceSession(
    const std::string& sessionName) {
  if (sessionName.empty()) {
    return;
  }

  // stop trace session
  stopKernelTraceSession(sessionName.c_str());

  // check if this can fail
  kernelTraceSession_ =
      std::make_shared<krabs::kernel_trace>(stringToWstring(sessionName));

  // Setting default trace session properties
  EVENT_TRACE_PROPERTIES session_properties = {0};
  session_properties.BufferSize = FLAGS_etw_kernel_trace_buffer_size;
  session_properties.MinimumBuffers = FLAGS_etw_kernel_trace_minimum_buffers;
  session_properties.MaximumBuffers = FLAGS_etw_kernel_trace_maximum_buffers;
  session_properties.FlushTimer = FLAGS_etw_kernel_trace_flush_timer;
  session_properties.LogFileMode = kEventTraceLogFileMode;
  kernelTraceSession_->set_trace_properties(&session_properties);
}

void KernelEtwSessionRunnable::stopKernelTraceSession(
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
  ControlTraceA(NULL,
                sessionName.c_str(),
                &sessionInfo.Properties,
                EVENT_TRACE_CONTROL_STOP);
}
} // namespace osquery
