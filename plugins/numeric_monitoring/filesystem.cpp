/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/format.hpp>

#include <osquery/core/flags.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/config/default_paths.h>
#include <plugins/numeric_monitoring/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {

FLAG(string,
     numeric_monitoring_filesystem_path,
     OSQUERY_LOG_HOME "numeric_monitoring.log",
     "File to dump numeric monitoring records one per line. "
     "The format of the line is <PATH><TAB><VALUE><TAB><TIMESTAMP>.");

REGISTER(NumericMonitoringFilesystemPlugin,
         monitoring::registryName(),
         "filesystem");

NumericMonitoringFilesystemPlugin::NumericMonitoringFilesystemPlugin()
    : NumericMonitoringFilesystemPlugin(
          FLAGS_numeric_monitoring_filesystem_path) {}

NumericMonitoringFilesystemPlugin::NumericMonitoringFilesystemPlugin(
    fs::path log_file_path
)
  : line_format_{
      monitoring::recordKeys().path,
      monitoring::recordKeys().value,
      monitoring::recordKeys().timestamp,
      monitoring::recordKeys().sync,
  }
  , separator_{'\t'}
  , log_file_path_(
      std::move(log_file_path)
  )
{
}

Status NumericMonitoringFilesystemPlugin::formTheLine(
    std::string& line, const PluginRequest& request) const {
  for (const auto& key : line_format_) {
    auto it = request.find(key);
    if (it == request.end()) {
      return Status(1, "Missing mandatory request field " + key);
    }
    line.append(it->second).push_back(separator_);
  }
  // remove last separator
  line.pop_back();
  return Status();
}

Status NumericMonitoringFilesystemPlugin::call(const PluginRequest& request,
                                               PluginResponse& response) {
  if (!isSetUp()) {
    return Status(1, "NumericMonitoringFilesystemPlugin is not set up");
  }
  auto line = std::string{};
  auto status = formTheLine(line, request);
  if (status.ok()) {
    std::unique_lock<std::mutex> lock(output_file_mutex_);
    output_file_stream_ << line << std::endl;
  }
  return status;
}

Status NumericMonitoringFilesystemPlugin::setUp() {
  output_file_stream_.open(log_file_path_.native(),
                           std::ios::out | std::ios::app | std::ios::binary);
  if (!output_file_stream_.is_open()) {
    return Status(
        1,
        boost::str(boost::format(
                       "Could not open file %s for numeric monitoring logs") %
                   log_file_path_));
  }
  return Status();
}

bool NumericMonitoringFilesystemPlugin::isSetUp() const {
  return output_file_stream_.is_open();
}

} // namespace osquery
