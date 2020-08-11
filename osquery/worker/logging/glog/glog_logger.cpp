/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "glog_logger.h"

#include <string>

#include <osquery/logger/logger.h>

namespace osquery {

GLOGLogger& GLOGLogger::instance() {
  static GLOGLogger logger;
  return logger;
}

void GLOGLogger::log(int severity, const std::string& message) {
  switch (severity) {
  case google::GLOG_ERROR: {
    LOG(ERROR) << message;
    break;
  }
  case google::GLOG_INFO: {
    LOG(INFO) << message;
    break;
  }
  case google::GLOG_WARNING: {
    LOG(WARNING) << message;
    break;
  }
  case google::GLOG_FATAL: {
    LOG(FATAL) << message;
    break;
  }
  default: {
    LOG(ERROR) << "severity " << severity << " not supported!";
    break;
  }
  }
}

void GLOGLogger::vlog(int priority, const std::string& message) {
  VLOG(priority) << message;
}

} // namespace osquery
