/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "glog_logger.h"

#include <string>

#include <osquery/logger.h>

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
