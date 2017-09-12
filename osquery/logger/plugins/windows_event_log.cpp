/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/windows_event_log.h"
#include "osquery/logger/plugins/windows_event_log_manifest/osquery.h"

namespace osquery {

REGISTER(WindowsEventLoggerPlugin, "logger", "windows_event_log");

WindowsEventLoggerPlugin::~WindowsEventLoggerPlugin() {
  releaseHandle(registration_handle_);
}

Status WindowsEventLoggerPlugin::logString(const std::string& s) {
  return emitLogRecord(registration_handle_, s);
}

Status WindowsEventLoggerPlugin::logStatus(
    const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    auto status = emitLogRecord(registration_handle_,
                                item.message,
                                item.severity,
                                item.filename,
                                item.line);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
    }
  }

  return Status(0, "OK");
}

void WindowsEventLoggerPlugin::init(const std::string& name,
                                    const std::vector<StatusLogLine>& log) {
  auto status = acquireHandle(registration_handle_);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return;
  }

  logStatus(log);
}

Status WindowsEventLoggerPlugin::acquireHandle(REGHANDLE& registration_handle) {
  auto status = EventRegister(
      &OsqueryWindowsEventLogProvider, nullptr, nullptr, &registration_handle);
  if (status != ERROR_SUCCESS) {
    registration_handle = 0;
    return Status(1, "Failed to register the Windows Event Log provider");
  }

  return Status(0, "Ok");
}

void WindowsEventLoggerPlugin::releaseHandle(REGHANDLE& registration_handle) {
  if (registration_handle != 0) {
    EventUnregister(registration_handle);
    registration_handle = 0;
  }
}

Status WindowsEventLoggerPlugin::emitLogRecord(
    REGHANDLE registration_handle,
    const std::string& message,
    StatusLogSeverity severity,
    const std::string& source_file_name,
    size_t line) {
  if (registration_handle == 0) {
    return Status(1, "The Windows Event Logger plugin is not initialized.");
  }

  EVENT_DATA_DESCRIPTOR data_descriptor[2] = {};
  EventDataDescCreate(&data_descriptor[0],
                      message.data(),
                      static_cast<ULONG>(message.size() + 1));

  auto location = source_file_name + ":" + std::to_string(line);
  EventDataDescCreate(&data_descriptor[1],
                      location.data(),
                      static_cast<ULONG>(location.size() + 1));

  const EVENT_DESCRIPTOR* event_descriptor = nullptr;
  switch (severity) {
  case O_WARNING: {
    event_descriptor = &WarningMessage;
    break;
  }

  case O_ERROR: {
    event_descriptor = &ErrorMessage;
    break;
  }

  case O_FATAL: {
    event_descriptor = &FatalMessage;
    break;
  }

  case O_INFO:
  default: {
    event_descriptor = &InfoMessage;
    break;
  }
  }

  auto status =
      EventWrite(registration_handle, event_descriptor, 2, data_descriptor);
  if (status != ERROR_SUCCESS) {
    auto error_message =
        std::string("Failed to publish the following log record: ") + location +
        " " + message;
    return Status(1, std::move(error_message));
  }

  return Status(0, "Ok");
}
}
