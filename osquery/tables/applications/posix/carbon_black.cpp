/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// Path to the Carbon Black sensor id file
#define kCbSensorIdFile "/var/lib/cb/sensor.id"
// Path to the Carbon Black sensor settings file
#define kCbSensorSettingsFile "/var/lib/cb/sensorsettings.ini"
// Path to Carbon Black directory
#define kCbDir "/var/lib/cb/"

// Get the Carbon Black sensor ID
void getSensorId(Row& r) {
  std::string file_contents;
  if (!forensicReadFile(kCbSensorIdFile, file_contents).ok()) {
    return;
  }
  // check to make sure we have sane data
  if (file_contents.length() != 16) {
    return;
  }

  unsigned int sensor_id;
  std::string hex_sensor_id = file_contents.substr(11, 16);
  std::stringstream converter(hex_sensor_id);
  converter >> std::hex >> sensor_id;
  r["sensor_id"] = INTEGER(sensor_id);
}

// Get settings of the Carbon Black sensor
void getSensorSettings(Row& r) {
  if (!pathExists(kCbSensorSettingsFile).ok()) {
    return;
  }
  boost::property_tree::ptree pt;
  try {
    boost::property_tree::ini_parser::read_ini(kCbSensorSettingsFile, pt);
  } catch (const boost::property_tree::ini_parser::ini_parser_error& e) {
    LOG(ERROR) << "Error parsing ini file: " << e.what();
    return;
  }

  auto const string_default = std::string{""};
  auto const int_default = std::string{"-1"};

  // After successful parsing, the values are extracted
  std::string config_name =
      pt.get<std::string>("CB.ConfigName", string_default);
  boost::replace_all(config_name, "%20", " ");
  r["config_name"] = SQL_TEXT(config_name);
  r["collect_store_files"] =
      INTEGER(pt.get<std::string>("CB.CollectStoreFiles", int_default));
  r["collect_module_loads"] =
      INTEGER(pt.get<std::string>("CB.CollectModuleLoads", int_default));
  r["collect_module_info"] =
      INTEGER(pt.get<std::string>("CB.CollectModuleInfo", int_default));
  r["collect_file_mods"] =
      INTEGER(pt.get<std::string>("CB.CollectFileMods", int_default));
  r["collect_reg_mods"] =
      INTEGER(pt.get<std::string>("CB.CollectRegMods", int_default));
  r["collect_net_conns"] =
      INTEGER(pt.get<std::string>("CB.CollectNetConns", int_default));
  r["collect_processes"] =
      INTEGER(pt.get<std::string>("CB.CollectProcesses", int_default));
  r["collect_cross_processes"] =
      INTEGER(pt.get<std::string>("CB.CollectCrossProcess", int_default));
  r["collect_emet_events"] =
      INTEGER(pt.get<std::string>("CB.CollectEmetEvents", int_default));
  std::string server =
      pt.get<std::string>("CB.SensorBackendServer", string_default);
  boost::replace_all(server, "%3A", ":");
  r["sensor_backend_server"] = SQL_TEXT(server);
  r["collect_data_file_writes"] = INTEGER(0);
  r["collect_processes"] = INTEGER(0);
  r["collect_sensor_operations"] = INTEGER(0);
  r["log_file_disk_quota_mb"] = INTEGER(0);
  r["log_file_disk_quota_percentage"] = INTEGER(0);
  r["protection_disabled"] = INTEGER(0);
  r["collect_process_user_context"] = INTEGER(0);
  r["sensor_ip_addr"] = SQL_TEXT("");
}

void getQueue(Row& r) {
  std::vector<std::string> files_list;
  if (!listFilesInDirectory(kCbDir, files_list, true)) {
    return;
  }
  uintmax_t binary_queue_size = 0;
  uintmax_t event_queue_size = 0;
  // Go through each file
  for (const auto& kfile : files_list) {
    fs::path file(kfile);
    if (file.filename() == "filedata" || file.filename() == "metadata") {
      binary_queue_size += fs::file_size(kfile);
    }
    if (file.stem() == "events") {
      event_queue_size += fs::file_size(kfile);
    }
  }
  r["binary_queue"] = INTEGER(binary_queue_size);
  r["event_queue"] = INTEGER(event_queue_size);
}

QueryData genCarbonBlackInfo(QueryContext& context) {
  Row r;
  QueryData results;

  getSensorId(r);
  getSensorSettings(r);
  getQueue(r);
  results.push_back(r);

  return results;
}
}
}
