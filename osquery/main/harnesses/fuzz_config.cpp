/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <malloc.h>

#include <chrono>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/main/harnesses/fuzz_utils.h>
#include <osquery/registry/registry_factory.h>

std::chrono::system_clock::time_point sample_start;
osquery::PluginRef option_plugin;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  sample_start = std::chrono::system_clock::now();
  auto result = osquery::osqueryFuzzerInitialize(argc, argv);

  option_plugin =
      osquery::RegistryFactory::get().plugin("config_parser", "options");

  if (option_plugin == nullptr) {
    throw std::runtime_error("Options plugin not registered");
  }

  return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string q((const char*)data, size);
  osquery::Config::get().update({{"fuzz", q}});

  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now() - sample_start)
                     .count();

  if (elapsed >= 5) {
    auto config_parser_plugin =
        std::dynamic_pointer_cast<osquery::ConfigParserPlugin>(option_plugin);
    config_parser_plugin->reset();
    osquery::Flag::instance().resetCustomFlags();
    malloc_trim(0);
    sample_start = std::chrono::system_clock::now();
  }

  return 0;
}
