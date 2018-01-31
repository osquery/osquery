/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>

#include <boost/noncopyable.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>

#include "osquery/core/process.h"

namespace osquery {

class TLSServerRunner : private boost::noncopyable {
 public:
  /// Create a singleton TLS server runner.
  static TLSServerRunner& instance() {
    static TLSServerRunner instance;
    return instance;
  }

  /// Set associated flags for testing client TLS usage.
  static void setClientConfig();

  /// Unset or restore associated flags for testing client TLS usage.
  static void unsetClientConfig();

  /// TCP port accessor.
  static const std::string& port() {
    return instance().port_;
  }

  /// Start the server if it hasn't started already.
  static void start();

  /// Stop the service when the process exits.
  static void stop();

 private:
  /// Current server handle.
  std::shared_ptr<PlatformProcess> server_{nullptr};

  /// Current server TLS port.
  std::string port_;

 private:
  std::string tls_hostname_;
  std::string enroll_tls_endpoint_;
  std::string tls_server_certs_;
  std::string enroll_secret_path_;
};
}