/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/dbus/methods/getstringproperty.h>
#include <osquery/tables/system/linux/dbus/methods/listunitsmethodhandler.h>
#include <osquery/tables/system/linux/dbus/uniquedbusconnection.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemItemPaths = {"/etc/xdg/autostart/"};
const std::vector<std::string> kSystemScriptPaths = {"/etc/init.d/"};

void parseDesktopEntry(const std::string& content, Row& r) {
  // Only keys in the [Desktop Entry] group describe the autostart item.
  // Other groups, such as [Desktop Action ...], reuse the same key names.
  // Keys that appear before any group header are kept, as before.
  bool in_desktop_entry = true;
  for (const auto& raw_line : osquery::split(content, "\n")) {
    // Trim before classifying the line: CRLF files leave a '\r' on every
    // line, and a group header may have trailing spaces.
    auto line = boost::algorithm::trim_copy(raw_line);
    if (line.empty() || line[0] == '#') {
      continue;
    }

    if (line[0] == '[') {
      in_desktop_entry = (line == "[Desktop Entry]");
      continue;
    }

    if (!in_desktop_entry) {
      continue;
    }

    // Split on the first '=' only. Values such as Exec commonly contain
    // more of them (for example "Exec=env FOO=bar app").
    auto pos = line.find('=');
    if (pos == std::string::npos) {
      continue;
    }

    auto key = boost::algorithm::trim_copy(line.substr(0, pos));
    auto value = boost::algorithm::trim_copy(line.substr(pos + 1));
    if (key == "Name") {
      r["name"] = std::move(value);
    } else if (key == "Exec") {
      r["path"] = std::move(value);
    }
  }
}

void genAutoStartItems(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    std::string content;
    if (readFile(file, content)) {
      parseDesktopEntry(content, r);
    }
    r["type"] = "Startup Item";
    r["status"] = "enabled";
    r["source"] = sysdir;

    auto username = osquery::split(sysdir, "/");
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

void genAutoStartScripts(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    r["name"] = osquery::split(file, "/").back();
    r["path"] = file;
    r["type"] = "Startup Item";
    r["status"] = "enabled";
    r["source"] = sysdir;
    auto username = osquery::split(sysdir, "/");
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

Status genSystemdItems(QueryData& results) {
  UniqueDbusConnection connection;
  auto status = UniqueDbusConnection::create(connection, true);
  if (!status.ok()) {
    return status;
  }

  ListUnitsMethod list_units_method;
  ListUnitsMethod::Output unit_list;
  status = list_units_method.call(
      unit_list, connection, "/org/freedesktop/systemd1");
  if (!status.ok()) {
    return status;
  }

  GetStringPropertyMethod get_string_property_method;

  for (const auto& unit : unit_list) {
    Row row = {};
    row["name"] = unit.id;
    row["type"] = "systemd unit";
    row["status"] = unit.active_state;

    std::string unit_path;
    status = get_string_property_method.call(unit_path,
                                             connection,
                                             unit.path,
                                             "org.freedesktop.systemd1.Unit",
                                             "FragmentPath");
    if (!status.ok()) {
      return status;
    }

    row["path"] = unit_path;

    std::string source_path;
    status = get_string_property_method.call(source_path,
                                             connection,
                                             unit.path,
                                             "org.freedesktop.systemd1.Unit",
                                             "SourcePath");
    if (!status.ok()) {
      return status;
    }

    row["source"] = source_path;

    std::string username;
    status = get_string_property_method.call(username,
                                             connection,
                                             unit.path,
                                             "org.freedesktop.systemd1.Service",
                                             "User");

    static_cast<void>(status);
    row["username"] = username;

    results.push_back(std::move(row));
  }

  return Status::success();
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // User specific
  for (const auto& dir : getHomeDirectories()) {
    auto itemsDir = dir / "/.config/autostart/";
    auto scriptsDir = dir / "/.config/autostart-scripts/";
    genAutoStartItems(itemsDir.string(), results);
    genAutoStartScripts(scriptsDir.string(), results);
  }

  // System specific
  for (const auto& dir : kSystemScriptPaths) {
    genAutoStartScripts(dir, results);
  }
  for (const auto& dir : kSystemItemPaths) {
    genAutoStartItems(dir, results);
  }

  auto status = genSystemdItems(results);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to enumerate the systemd services: "
               << status.getMessage();
  }

  return results;
}

} // namespace tables
} // namespace osquery
