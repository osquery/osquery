/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// clang-format off

#include <osquery/utils/system/system.h>
#include <evntprov.h>
// clang-format on

#include <osquery/flags.h>
#include <osquery/plugins/logger.h>

namespace osquery {

class WindowsEventLoggerPlugin : public LoggerPlugin {
 public:
  virtual ~WindowsEventLoggerPlugin();

  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override;
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 public:
  /// Registers the process as a Windows Event Log provider
  static Status acquireHandle(REGHANDLE& registration_handle);

  /// Releases the Windows Event Log provider handle
  static void releaseHandle(REGHANDLE& registration_handle);

  /// Emits a single log record to the Windows Event Log
  static Status emitLogRecord(
      REGHANDLE registration_handle,
      const std::string& message,
      StatusLogSeverity severity = O_INFO,
      const std::string& source_file_name = std::string("<empty>"),
      size_t line = 0U);

 private:
  REGHANDLE registration_handle_{0};
};
}
