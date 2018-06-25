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

#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include <osquery/numeric_monitoring.h>

namespace osquery {

class NumericMonitoringFilesystemPlugin : public NumericMonitoringPlugin {
 public:
  explicit NumericMonitoringFilesystemPlugin();
  explicit NumericMonitoringFilesystemPlugin(
      boost::filesystem::path log_file_path);

  Status call(const PluginRequest& request, PluginResponse& response) override;

  Status setUp() override;

  bool isSetUp() const;

 private:
  Status formTheLine(std::string& line, const PluginRequest& request) const;

 private:
  const std::vector<std::string> line_format_;
  const std::string::value_type separator_;
  const boost::filesystem::path log_file_path_;
  std::ofstream output_file_stream_;
  std::mutex output_file_mutex_;
};

} // namespace osquery
