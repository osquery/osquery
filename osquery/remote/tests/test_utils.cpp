/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <csignal>
#include <ctime>

#include <thread>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/sql/sql.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_string(enroll_tls_endpoint);
DECLARE_string(tls_server_certs);
DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_caching);

Status TLSServerRunner::startAndSetScript(const std::string& port,
                                          const std::string& server_cert) {
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

  args.push_back(port);

  const auto cmd = osquery::join(args, " ");
  server_ = PlatformProcess::launchTestPythonScript(cmd);
  if (server_ == nullptr) {
    return Status::failure("Cannot create test python script: " + cmd);
  }
  return Status::success();
}

Status TLSServerRunner::getListeningPortPid(const std::string& port,
                                            std::string& pid) {
  // Reset the output.
  pid.clear();

  std::string q = "select pid from listening_ports where port = '" + port + "'";

  auto caching = FLAGS_disable_caching;
  FLAGS_disable_caching = true;
  auto results = SQL(q);
  FLAGS_disable_caching = caching;
  if (results.rows().empty()) {
    return Status::failure("No pid listening on port: " + port);
  }

  const auto& first_row = results.rows()[0];
  pid = first_row.at("pid");
  return Status::success();
}

bool TLSServerRunner::start(const std::string& server_cert) {
  auto& self = instance();
  if (self.server_ != nullptr) {
    return true;
  }

  // We need to pick a 'random' port.
  std::srand((unsigned int)getUnixTime());

  bool started = false;
  const size_t max_retry = 3;
  size_t retry = 0;
  while (retry < max_retry) {
    // Pick a port in an ephemeral range at random.
    self.port_ = std::to_string(std::rand() % 10000 + 20000);

    {
      // Check that the port is not used.
      std::string pid;
      if (self.getListeningPortPid(self.port_, pid).ok()) {
        // Another process is listening on this port.
        continue;
      }
    }

    auto status = self.startAndSetScript(self.port_, server_cert);
    if (!status.ok()) {
      // This is an unexpected problem, retry without waiting.
      LOG(WARNING) << status.getMessage();
      continue;
    }

    size_t delay = 0;
    // Expect to wait for the server to listen on the port.
    while (delay < max_retry * 2 * 1000) {
      std::string pid;
      status = self.getListeningPortPid(self.port_, pid);
      if (!status.ok()) {
        // No pid listening, we should wait longer.
        LOG(WARNING) << status.getMessage();
        sleepFor(100);
        delay += 100;
        continue;
      }

      if (pid == std::to_string(self.server_->pid())) {
        started = true;
      } else {
        // Another process is listening on this pid.
        LOG(WARNING) << "Another process is listening on port: " << self.port_;
      }
      break;
    }

    if (started) {
      break;
    }

    self.stop();
    sleepFor(1000);
    ++retry;
  }

  if (!started) {
    return false;
  }
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
    self.server_.reset();
  }
}
} // namespace osquery
