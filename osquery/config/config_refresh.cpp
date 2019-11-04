/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config.h>
#include <osquery/config/config_refresh.h>
#include <osquery/core/init.h>
#include <osquery/flagalias.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

CLI_FLAG(bool,
         config_check,
         false,
         "Check the format of an osquery config and exit");

CLI_FLAG(bool, config_dump, false, "Dump the contents of the configuration");

CLI_FLAG(uint64,
         config_refresh,
         0,
         "Optional interval in seconds to re-read configuration");
FLAG_ALIAS(google::uint64, config_tls_refresh, config_refresh);

/// How long to wait when config update fails
CLI_FLAG(uint64,
         config_accelerated_refresh,
         300,
         "Interval to wait if reading a configuration fails");

FLAG_ALIAS(google::uint64,
           config_tls_accelerated_refresh,
           config_accelerated_refresh);

DECLARE_bool(config_check);
DECLARE_bool(config_enable_backup);

void ConfigRefreshRunner::start() {
  while (!interrupted()) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    pause(std::chrono::seconds(refresh_sec_));
    // Since the pause occurs before the logic, we need to check for an
    // interruption request.
    if (interrupted()) {
      return;
    }

    VLOG(1) << "Refreshing configuration state";
    refresh();
  }
}

Status ConfigRefreshRunner::refresh() {
  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  WriteLock lock(config_refresh_mutex_);
  if (!status.ok()) {
    if (FLAGS_config_refresh > 0 && getRefresh() == FLAGS_config_refresh) {
      VLOG(1) << "Using accelerated configuration delay";
      setRefresh(FLAGS_config_accelerated_refresh);
    }

    Config::get().loaded(true);
    if (FLAGS_config_enable_backup && first_.exchange(false)) {
      LOG(INFO) << "Backing up configuration";
      const auto result = Config::get().restoreConfigBackup();
      if (!result) {
        return Status::failure(result.getError().getMessage());
      } else {
        Config::get().update(*result);
      }
    }
    return status;
  } else if (getRefresh() != FLAGS_config_refresh) {
    VLOG(1) << "Normal configuration delay restored";
    setRefresh(FLAGS_config_refresh);
  }

  // if there was a response, parse it and update internal state
  Config::get().valid(true);
  if (response.size() > 0) {
    if (FLAGS_config_dump) {
      // If config checking is enabled, debug-write the raw config data.
      for (const auto& content : response[0]) {
        fprintf(stdout,
                "{\"%s\": %s}\n",
                content.first.c_str(),
                content.second.c_str());
      }
      // Don't force because the config plugin may have started services.
      Initializer::requestShutdown();
      return Status::success();
    }
    status = Config::get().update(response[0]);
  }

  first_ = false;
  Config::get().loaded(true);
  return status;
}

void ConfigRefreshRunner::setRefresh(size_t refresh_sec) {
  refresh_sec_ = refresh_sec;
}

size_t ConfigRefreshRunner::getRefresh() const {
  return refresh_sec_;
}

Status startAndLoadConfig() {
  // valid_ = false;
  auto config_plugin = RegistryFactory::get().getActive("config");
  if (!RegistryFactory::get().exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  auto refresh_runner_ = std::make_shared<ConfigRefreshRunner>();

  /*
   * If the initial configuration includes a non-0 refresh, start an
   * additional service that sleeps and periodically regenerates the
   * configuration.
   */
  if (!FLAGS_config_check && FLAGS_config_refresh > 0) {
    refresh_runner_->setRefresh(FLAGS_config_refresh);
    Dispatcher::addService(refresh_runner_);
  }

  return refresh_runner_->refresh();
}

} // namespace osquery
