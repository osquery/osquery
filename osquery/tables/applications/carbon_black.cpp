/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables.h>
#include <osquery/core.h>
#include <osquery/filesystem.h>
#ifdef WIN32
#include <osquery/tables/system/windows/registry.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/predicate.hpp>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// Carbon Black registry path 
#define kCbRegLoc "SOFTWARE\\CarbonBlack\\config"
// Path to the Carbon Black sensor id file
#define kCbSensorIdFile "/var/lib/cb/sensor.id"
// Path to the Carbon Black sensor settings file
#define kCbSensorSettingsFile "/var/lib/cb/sensorsettings.ini"
// Path to Carbon Black direcotry
#ifdef WIN32
#define kCbDir "C:\\Windows\\CarbonBlack\\"
#else
#define kCbDir "/var/lib/cb/"
#endif


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
    if (!boost::filesystem::exists(kCbSensorSettingsFile)) {
        return;
    }
    boost::property_tree::ptree pt;
    boost::property_tree::ini_parser::read_ini(kCbSensorSettingsFile, pt);
    r["config_name"] = SQL_TEXT(pt.get<std::string>("CB.ConfigName"));
    r["collect_store_files"] = INTEGER(pt.get<std::string>("CB.CollectStoreFiles"));
    r["collect_module_loads"] = INTEGER(pt.get<std::string>("CB.CollectModuleLoads"));
    r["collect_module_info"] = INTEGER(pt.get<std::string>("CB.CollectModuleInfo"));
    r["collect_file_mods"] = INTEGER(pt.get<std::string>("CB.CollectFileMods"));
    r["collect_reg_mods"] = INTEGER(pt.get<std::string>("CB.CollectRegMods"));
    r["collect_net_conns"] = INTEGER(pt.get<std::string>("CB.CollectNetConns"));
    r["collect_processes"] = INTEGER(pt.get<std::string>("CB.CollectProcesses"));
    r["collect_cross_processes"] = INTEGER(pt.get<std::string>("CB.CollectCrossProcess"));
    r["collect_emet_events"] = INTEGER(pt.get<std::string>("CB.CollectEmetEvents"));
    std::string server = pt.get<std::string>("CB.SensorBackendServer");
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
    auto status = listFilesInDirectory(kCbDir, files_list, true);
    if (!status.ok()) {
        return;
    }
    unsigned int binary_queue_size = 0;
    unsigned int event_queue_size = 0;
    // Go through each file
    for (const auto& kfile : files_list) {
        fs::path file(kfile);
        if (file.filename() == "filedata" ||
            file.filename() == "metadata" ||
            file.filename() == "data" ||
            file.filename() == "info.txt") {

            binary_queue_size += fs::file_size(kfile);
        }
        if (file.stem() == "events" ||
            file.filename() == "active-event.log" ||
            boost::starts_with(file.filename().c_str(), "eventlog_")) {
            event_queue_size += fs::file_size(kfile);
        }
    }
    r["binary_queue"] = INTEGER(binary_queue_size);
    r["event_queue"] = INTEGER(event_queue_size);
}

#ifdef WIN32
void getWinSettings(Row& r) {
    QueryData results;
    queryKey("HKEY_LOCAL_MACHINE", kCbRegLoc, results);
    for (const auto& kKey : results) {
        if (kKey.at("name") == "CollectCrossProcess") {
            r["collect_cross_processes"] = SQL_TEXT(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectStoreFiles") {
            r["collect_store_files"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectDataFileWrites") {
            r["collect_data_file_writes"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectEmetEvents") {
            r["collect_emet_events"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectFileMods") {
            r["collect_file_mods"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectModuleInfo") {
            r["collect_module_info"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectModuleLoads") {
            r["collect_module_loads"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectNetConns") {
            r["collect_net_conns"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectProcesses") {
            r["collect_processes"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectProcessUserContext") {
            r["collect_process_user_context"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectRegMods") {
            r["collect_reg_mods"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectSensorOperations") {
            r["collect_sensor_operations"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "CollectStoreFiles") {
            r["collect_store_files"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "ConfigName") {
            r["config_name"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "LogFileDiskQuotaMb") {
            r["log_file_disk_quota_mb"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "LogFileDiskQuotaPercentage") {
            r["log_file_disk_quota_percentage"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "ProtectionDisabled") {
            r["protection_disabled"] = INTEGER(kKey.at("data"));
        }
        if (kKey.at("name") == "SensorIpAddr") {
            r["sensor_ip_addr"] = SQL_TEXT(kKey.at("data"));
        }
        if (kKey.at("name") == "SensorBackendServer") {
            std::string server = kKey.at("data");
            boost::replace_all(server, "%3A", ":");
            r["sensor_backend_server"] = SQL_TEXT(server);
        }
        if (kKey.at("name") == "SensorId") {
            // from a string to an int, to hex, a portion of the hex, then to int
            uint64_t int_sensor_id = strtoll(kKey.at("data").c_str(), NULL, 10);
            std::stringstream hex_sensor_id;
            hex_sensor_id << std::hex << int_sensor_id;
            unsigned int sensor_id;
            std::string small_hex_sensor_id = hex_sensor_id.str().substr(11,16);
            std::stringstream converter(small_hex_sensor_id);
            converter >> std::hex >> sensor_id;
            r["sensor_id"] = INTEGER(sensor_id);
        }
    }
}
#endif

QueryData genInfo(QueryContext &context) {
    Row r;
    QueryData results;

#ifdef WIN32
    getWinSettings(r);
#else
    getSensorId(r);
    getSensorSettings(r);
#endif
    getQueue(r);
    results.push_back(r);

    return results;
}
}
}