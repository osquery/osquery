/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/process/process.h>

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

  /**
   * Start the server if it hasn't started already.
   * The server binds to port zero and publishes the assigned port without
   * releasing its listening socket.
   *
   * A failure status is returned on error.
   */
  static bool start(const std::string& server_cert = {},
                    bool verify_client_cert = false,
                    bool require_gzip = false);

  /// Stop the service when the process exits.
  static void stop();

 private:
  /**
   * Try to start the TLS server and set ::server_ to the process.
   *
   * A failure status is returned if the process is not created.
   * This does not check that the port was bound.
   */
  Status startAndSetScript(const std::string& port_file,
                           const std::string& server_cert,
                           bool verify_client_cert,
                           bool require_gzip = false);

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
} // namespace osquery
