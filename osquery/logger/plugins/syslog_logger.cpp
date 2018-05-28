/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <syslog.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

FLAG(int32,
     logger_syslog_facility,
     LOG_LOCAL3 >> 3,
     "Syslog facility for status and results logs (0-23, default 19)");

FLAG(bool,
     logger_syslog_prepend_cee,
     false,
     "Prepend @cee: tag to logged JSON messages");

class SyslogLoggerPlugin : public LoggerPlugin {
 public:
  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override;
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;
  Status logStatus(const std::vector<StatusLogLine>& log) override;
};

REGISTER(SyslogLoggerPlugin, "logger", "syslog");

Status SyslogLoggerPlugin::logString(const std::string& s) {
  if (FLAGS_logger_syslog_prepend_cee) {
    syslog(LOG_INFO, "@cee:%s", s.c_str());
  } else {
    syslog(LOG_INFO, "%s", s.c_str());
  }
  return Status(0, "OK");
}

Status SyslogLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    int severity = LOG_NOTICE;
    if (item.severity == O_INFO) {
      severity = LOG_NOTICE;
    } else if (item.severity == O_WARNING) {
      severity = LOG_WARNING;
    } else if (item.severity == O_ERROR) {
      severity = LOG_ERR;
    } else if (item.severity == O_FATAL) {
      severity = LOG_CRIT;
    }

    std::string line = "severity=" + std::to_string(item.severity) +
                       " location=" + item.filename + ":" +
                       std::to_string(item.line) + " message=" + item.message;

    syslog(severity, "%s", line.c_str());
  }
  return Status(0, "OK");
}

void SyslogLoggerPlugin::init(const std::string& name,
                              const std::vector<StatusLogLine>& log) {
  closelog();

  // Define the syslog/target's application name.
  if (FLAGS_logger_syslog_facility < 0 || FLAGS_logger_syslog_facility > 23) {
    FLAGS_logger_syslog_facility = LOG_LOCAL3 >> 3;
  }
  openlog(name.c_str(), LOG_PID | LOG_CONS, FLAGS_logger_syslog_facility << 3);

  // Now funnel the intermediate status logs provided to `init`.
  logStatus(log);
}
}
