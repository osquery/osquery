/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "syslog_logger.h"

#include <syslog.h>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

FLAG(int32,
     logger_syslog_facility,
     LOG_LOCAL3 >> 3,
     "Syslog facility for status and results logs (0-23, default 19)");

FLAG(bool,
     logger_syslog_prepend_cee,
     false,
     "Prepend @cee: tag to logged JSON messages");

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
