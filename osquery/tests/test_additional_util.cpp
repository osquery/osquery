/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <signal.h>
#include <time.h>

#include <thread>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_string(enroll_tls_endpoint);
DECLARE_string(tls_server_certs);
DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_caching);

void TLSServerRunner::start() {
  auto& self = instance();
  if (self.server_ != 0) {
    return;
  }

  // Pick a port in an ephemeral range at random.
  self.port_ = std::to_string(rand() % 10000 + 20000);

  // Fork then exec a shell.
  auto python_server = (fs::path(kTestDataPath) / "test_http_server.py")
                           .make_preferred()
                           .string() +
                       " --tls " + self.port_;
  self.server_ = PlatformProcess::launchTestPythonScript(python_server);
  if (self.server_ == nullptr) {
    return;
  }

  size_t delay = 0;
  std::string query =
      "select pid from listening_ports where port = '" + self.port_ + "'";
  while (delay < 2 * 1000) {
    auto caching = FLAGS_disable_caching;
    FLAGS_disable_caching = true;
    auto results = SQL(query);
    FLAGS_disable_caching = caching;
    if (results.rows().size() > 0) {
      self.server_.reset(
          new PlatformProcess(std::atoi(results.rows()[0].at("pid").c_str())));
      break;
    }

    sleepFor(100);
    delay += 100;
  }
}

void TLSServerRunner::setClientConfig() {
  auto& self = instance();

  self.tls_hostname_ = Flag::getValue("tls_hostname");
  Flag::updateValue("tls_hostname", "localhost:" + port());

  self.enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
  Flag::updateValue("enroll_tls_endpoint", "/enroll");

  self.tls_server_certs_ = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs",
                    (fs::path(kTestDataPath) / "test_server_ca.pem")
                        .make_preferred()
                        .string());

  self.enroll_secret_path_ = Flag::getValue("enroll_secret_path");
  Flag::updateValue("enroll_secret_path",
                    (fs::path(kTestDataPath) / "test_enroll_secret.txt")
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
}
