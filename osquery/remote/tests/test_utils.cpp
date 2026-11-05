/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>

#include <boost/filesystem.hpp>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/remote/requests.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/remote/transports/tls.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/time.h>

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_string(enroll_tls_endpoint);
DECLARE_string(tls_server_certs);
DECLARE_string(enroll_secret_path);

Status TLSServerRunner::startAndSetScript(const std::string& port_file,
                                          const std::string& server_cert,
                                          bool verify_client_cert,
                                          bool require_gzip) {
  auto script = (getTestHelperScriptsDirectory() / "test_http_server.py");
  auto config_dir = getTestConfigDirectory();
  std::vector<std::string> args = {
      script.make_preferred().string(),
      "--tls",
      "--verbose",
      "--test-configs-dir",
      config_dir.make_preferred().string(),
  };

  if (!server_cert.empty()) {
    args.push_back("--cert");
    args.push_back(server_cert);
  }

  if (verify_client_cert) {
    args.push_back("--verify-client-cert");
  }

  if (require_gzip) {
    args.push_back("--require-gzip");
  }

  args.push_back("--port-file");
  args.push_back(port_file);
  args.push_back("0");

  server_ = PlatformProcess::launchPythonScript(args);
  if (server_ == nullptr) {
    return Status::failure("Cannot create test python script: " +
                           osquery::join(args, " "));
  }
  return Status::success();
}

bool TLSServerRunner::start(const std::string& server_cert,
                            bool verify_client_cert,
                            bool require_gzip) {
  auto& self = instance();
  if (self.server_ != nullptr) {
    return true;
  }

  auto readiness_dir = boost::filesystem::temp_directory_path() /
                       boost::filesystem::unique_path("osquery-tls-%%%%-%%%%");
  if (!boost::filesystem::create_directory(readiness_dir)) {
    LOG(ERROR) << "Cannot create TLS test server readiness directory";
    return false;
  }
  auto cleanup = scope_guard::create(
      [&readiness_dir] { boost::filesystem::remove_all(readiness_dir); });
  auto port_file = (readiness_dir / "port").string();
  auto start_status = self.startAndSetScript(
      port_file, server_cert, verify_client_cert, require_gzip);
  if (!start_status.ok()) {
    LOG(ERROR) << start_status.getMessage();
    return false;
  }

  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
  while (!boost::filesystem::exists(port_file)) {
    int exit_status{0};
    auto process_state = self.server_->checkStatus(exit_status);
    if (process_state == PROCESS_EXITED) {
      LOG(ERROR) << "TLS test server exited before publishing its port: "
                 << exit_status;
      self.server_.reset();
      self.port_.clear();
      return false;
    }
    if (process_state == PROCESS_ERROR) {
      LOG(ERROR) << "Cannot check TLS test server process status";
      self.stop();
      return false;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      LOG(ERROR) << "TLS test server did not publish its bound port in time";
      self.stop();
      return false;
    }
    sleepFor(100);
  }

  std::string assigned_port;
  auto read_status = readFile(port_file, assigned_port);
  auto port = tryTo<int>(assigned_port);
  if (!read_status.ok() || port.isError() || port.get() <= 0 ||
      port.get() > 65535) {
    LOG(ERROR) << "TLS test server published an invalid port: "
               << assigned_port;
    self.stop();
    return false;
  }
  self.port_ = assigned_port;

  const size_t max_retry = 3;
  size_t retry = 0;

  LOG(WARNING) << "Python server process started correctly";

  // Verify that the server is also actually ready to serve
  retry = 0;
  bool ready_to_serve = false;

  /* Temporarily configure the test certificates,
     so that the client doesn't immediately fail
     for not finding certificate files */
  std::string client_cert = Flag::getValue("tls_client_cert");
  Flag::updateValue(
      "tls_client_cert",
      (getTestConfigDirectory() / "test_client.pem").make_preferred().string());

  std::string client_key = Flag::getValue("tls_client_key");
  Flag::updateValue(
      "tls_client_key",
      (getTestConfigDirectory() / "test_client.key").make_preferred().string());

  std::string server_ca_certs = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs",
                    (getTestConfigDirectory() / "test_server_ca.pem")
                        .make_preferred()
                        .string());

  while (retry < max_retry) {
    std::string ping_server_uri =
        "https://localhost:" + std::string(self.port_);

    Request<TLSTransport, JSONSerializer> request(ping_server_uri);
    Status status = request.call();

    /* The provided client settings won't always make us succeed
       in establishing a correct TLS connection,
       but we assume that if it's not a timeout,
       then the server is ready enough. */
    if (!status.ok()) {
      if (status.getMessage().find("Operation timed out") !=
          std::string::npos) {
        LOG(WARNING) << "Python HTTP Server not ready yet";
        sleepFor(5000);
        ++retry;
        continue;
      } else {
        /* We still log this failure to see what was the issue,
           but in theory the server is ready to serve. */
        LOG(WARNING) << "Failed to ping: " << status.getMessage();
      }
    }

    ready_to_serve = true;
    break;
  }

  Flag::updateValue("tls_client_cert", client_cert);
  Flag::updateValue("tls_client_key", client_key);
  Flag::updateValue("tls_server_certs", server_ca_certs);

  if (!ready_to_serve) {
    LOG(ERROR) << "The Python server was not ready to serve in time";
    self.stop();
    return false;
  }

  LOG(WARNING) << "Server is now ready to serve";

  return true;
}

void TLSServerRunner::setClientConfig() {
  auto& self = instance();

  self.tls_hostname_ = Flag::getValue("tls_hostname");
  Flag::updateValue("tls_hostname", "localhost:" + port());

  self.enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
  Flag::updateValue("enroll_tls_endpoint", "/enroll");

  self.tls_server_certs_ = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs",
                    (getTestConfigDirectory() / "test_server_ca.pem")
                        .make_preferred()
                        .string());

  self.enroll_secret_path_ = Flag::getValue("enroll_secret_path");
  Flag::updateValue("enroll_secret_path",
                    (getTestConfigDirectory() / "test_enroll_secret.txt")
                        .make_preferred()
                        .string());

  Flag::updateValue(
      "tls_client_cert",
      (getTestConfigDirectory() / "test_client.pem").make_preferred().string());

  Flag::updateValue(
      "tls_client_key",
      (getTestConfigDirectory() / "test_client.key").make_preferred().string());
}

void TLSServerRunner::unsetClientConfig() {
  auto& self = instance();
  Flag::updateValue("tls_hostname", self.tls_hostname_);
  Flag::updateValue("enroll_tls_endpoint", self.enroll_tls_endpoint_);
  Flag::updateValue("tls_server_certs", self.tls_server_certs_);
  Flag::updateValue("enroll_secret_path", self.enroll_secret_path_);
}

void TLSServerRunner::stop() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    self.server_->kill();
    if (!self.server_->cleanup(std::chrono::seconds(5))) {
      LOG(ERROR) << "Cannot reap TLS test server process";
    }
    self.server_.reset();
  }
  self.port_.clear();
}
} // namespace osquery
