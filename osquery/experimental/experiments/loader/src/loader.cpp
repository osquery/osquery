/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/experiments/loader.h>
#include <osquery/logger/logger.h>

#ifdef __linux__
#include <osquery/experiments/linuxevents.h>
#endif

#include <boost/algorithm/string.hpp>

#include <unordered_map>

namespace osquery {

FLAG(string,
     experiment_list,
     "",
     "Comma-separated list of experiments to enable");

namespace {

using ExperimentInitializer = void (*)();

// clang-format off
static std::unordered_map<std::string, ExperimentInitializer> kExperimentMap = {
#ifdef __linux__
  {"linuxevents", initializeLinuxEvents}
#endif
};
// clang-format on

} // namespace

void loadExperiments() {
  if (FLAGS_experiment_list.empty()) {
    VLOG(1) << "No experiments selected";
    return;
  }

  std::vector<std::string> experiment_list;
  boost::split(experiment_list, FLAGS_experiment_list, boost::is_any_of(","));

  if (experiment_list.empty()) {
    return;
  }

  LOG(INFO)
      << "Experiments are enabled. This osquery instance is not officially "
         "supported";

  std::sort(experiment_list.begin(), experiment_list.end());
  experiment_list.erase(
      std::unique(experiment_list.begin(), experiment_list.end()),
      experiment_list.end());

  for (const auto& experiment : experiment_list) {
    auto initializer_it = kExperimentMap.find(experiment);
    if (initializer_it == kExperimentMap.end()) {
      LOG(ERROR) << "The following experiment was not found: " << experiment;
      continue;
    }

    LOG(INFO) << "Enabling experiment: " << experiment;

    const auto& initializer = initializer_it->second;
    initializer();
  }
}

} // namespace osquery
