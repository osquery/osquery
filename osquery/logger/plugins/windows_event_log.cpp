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
  if (registration_handle_ != 0) {
    EventUnregister(registration_handle_);
  }
}

Status WindowsEventLoggerPlugin::logString(const std::string& s) {
  StatusLogLine log_line = {};
  log_line.severity = O_INFO;
  log_line.filename = "<empty>";
  log_line.message = s;

  std::vector<StatusLogLine> log_record = { std::move(log_line) };
  return logStatus(log_record);
}

Status WindowsEventLoggerPlugin::logStatus(
    const std::vector<StatusLogLine>& log) {
  if (registration_handle_ == 0) {
    return Status(0, "The Windows Event Logger plugin is not initialized.");
  }

  size_t i = 0;
  for (const auto& item : log) {
    EVENT_DATA_DESCRIPTOR data_descriptor[2] = {};
    EventDataDescCreate(&data_descriptor[0], item.message.data(), static_cast<ULONG>(item.message.size() + 1));

    auto location = item.filename + ":" + std::to_string(item.line);
    EventDataDescCreate(&data_descriptor[1], location.data(), static_cast<ULONG>(location.size() + 1));

    const EVENT_DESCRIPTOR  *event_descriptor = nullptr;
    switch (item.severity) {
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

    auto status = EventWrite(registration_handle_, event_descriptor, 2, data_descriptor);
    if (status != ERROR_SUCCESS) {
      LOG(ERROR) << "Failed to publish the following log record: " << location << " " << item.message.data();
    }
  }

  return Status(0, "OK");
}

void WindowsEventLoggerPlugin::init(const std::string& name,
                                    const std::vector<StatusLogLine>& log) {
  auto status = EventRegister(&OsqueryWindowsEventLogProvider, nullptr, nullptr, &registration_handle_);
  if (status != ERROR_SUCCESS) {
    LOG(ERROR) << "Failed to register the Windows Event Log provider";
    return;
  }

  logStatus(log);
}
}
